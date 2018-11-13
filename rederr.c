/* SPDX-License-Identifier: LGPL-2.1+ */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/sockios.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Invokes a process as a child, with its stdout and stderr connected to a pair of AF_UNIX/SOCK_DGRAM sockets which
 * both are connected to a third AF_UNIX/SOCK_DGRAM socket we listen on. Since the two stdout/stderr sockets are bound
 * to different AF_UNIX "auto-bind" addresses any datagrams sent over them will be read by us coming from different
 * sender addresses. This allows us to maintain a single, ordered stream of stdout/stderr write ops, but still know
 * which datagram was an stdout and which an stderr write. We use that information to output data from stderr in red,
 * while leaving the data from stdout in the default color.
 *
 * Or in other words, this invokes a program and colors its stderr output red.
 *
 * Caveats:
 *
 * → Since stdout/stderr of the invoked processes are sockets these process might disable automatic flushing (like
 *   glibc stdio might).
 *
 * → For the same reason open("/proc/self/fd/1") and open("/proc/self/fd/2") is not going to work (as sockets may not
 *   be open()ed). This means shell scripts that use 'echo foo > /dev/stderr' will not be happy (but such scripts are
 *   slightly ugly anyway, and should rather use 'echo foo >&2').
 *
 * → Since stdout/stderr is not a TTY there's no real interactivity. Programs that become interactive when invoked on a
 *   tty (such as most shells) will hence remain in non-interactive mode.
 *
 */

#define ANSI_RED "\x1B[0;1;31m"
#define ANSI_NORMAL "\x1B[0m"

union sockaddr_union {
        struct sockaddr sa;
        struct sockaddr_un un;
        uint8_t buffer[sizeof(struct sockaddr_un) + 1]; /* AF_UNIX socket paths don't have to be NUL terminated */
};

static int connect_socket(
                const struct sockaddr *sa, socklen_t salen,
                union sockaddr_union *ret_bound, socklen_t *ret_bound_len) {

        int fd = -1, r;
        socklen_t k;

        assert(sa);
        assert(salen > 0);
        assert(ret_bound);
        assert(ret_bound_len);

        /* Allocates an AF_UNIX/SOCK_DGRAM socket and connects it the specified address, after using the auto-bind
         * logic to acquire a local address. */

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0) {
                r = -errno;
                fprintf(stderr, "Failed to allocate stdout sending socket: %m\n");
                goto fail;
        }

        assert(salen >= sizeof(sa_family_t));
        assert(sa->sa_family == AF_UNIX);

        /* We reuse the socket address we are connecting to here, as for Linux' auto-bind feature we just need a
         * structure with AF_UNIX in the .sa_family field, and we know this one qualifies. */
        if (bind(fd, sa, sizeof(sa_family_t)) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to bind socket: %m\n");
                goto fail;
        }

        if (connect(fd, sa, salen) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to connect to our own socket: %m\n");
                goto fail;
        }

        k = sizeof(union sockaddr_union);
        if (getsockname(fd, &ret_bound->sa, &k) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to get auto-bound socket address: %m\n");
                goto fail;
        }

        if (shutdown(fd, SHUT_RD) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to shut down read side of socket: %m\n");
                goto fail;
        }

        *ret_bound_len = k;
        return fd;

fail:
        if (fd >= 0)
                (void) close(fd);

        return r;
}

static int allocate_sockets(
                int *ret_recv_fd, int *ret_send1_fd, int *ret_send2_fd,
                union sockaddr_union *ret_send1_sa, socklen_t *ret_send1_salen,
                union sockaddr_union *ret_send2_sa, socklen_t *ret_send2_salen) {

        int r, recv_fd = -1, send1_fd = -1, send2_fd = -1, k;
        bool directory_made = false, socket_bound = false;
        char directory[] = "/tmp/rederr.XXXXXX";
        socklen_t recv_salen, send1_salen, send2_salen;
        union sockaddr_union recv_sa = {
                .un.sun_family = AF_UNIX,
        }, send1_sa, send2_sa;

        assert(ret_recv_fd);
        assert(ret_send1_fd);
        assert(ret_send2_fd);
        assert(ret_send1_sa);
        assert(ret_send1_salen);
        assert(ret_send2_sa);
        assert(ret_send2_salen);

        if (!mkdtemp(directory)) {
                r = -errno;
                fprintf(stderr, "Failed to create temporary directory: %m\n");
                goto fail;
        }

        directory_made = true;

        k = snprintf(recv_sa.un.sun_path, sizeof(recv_sa.un.sun_path), "%s/sock", directory);
        assert(k >= 0);
        assert((size_t) k <= sizeof(recv_sa.un.sun_path));
        recv_salen = offsetof(struct sockaddr_un, sun_path) + k + 1;

        recv_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (recv_fd < 0) {
                r = -errno;
                fprintf(stderr, "Failed to allocate reception socket: %m\n");
                goto fail;
        }

        if (bind(recv_fd, &recv_sa.sa, recv_salen) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to bind socket: %m\n");
                goto fail;
        }

        socket_bound = true;

        /* Now connect two sending socket to this. We'll use one for stdout and one for stderr of the child process we fork off */
        send1_fd = connect_socket(&recv_sa.sa, recv_salen, &send1_sa, &send1_salen);
        if (send1_fd < 0) {
                r = send1_fd;
                goto fail;
        }

        send2_fd = connect_socket(&recv_sa.sa, recv_salen, &send2_sa, &send2_salen);
        if (send2_fd < 0) {
                r = send2_fd;
                goto fail;
        }

        /* Now, let's remove the socket and its temporary directory, so that we know that nobody else can connect anymore */
        if (unlink(recv_sa.un.sun_path) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to unlink socket: %m\n");
                goto fail;
        }

        if (rmdir(directory) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to remove temporary directory: %m\n");
                goto fail;
        }

        *ret_recv_fd = recv_fd;
        *ret_send1_fd = send1_fd;
        *ret_send2_fd = send2_fd;

        memcpy(ret_send1_sa, &send1_sa, send1_salen);
        *ret_send1_salen = send1_salen;

        memcpy(ret_send2_sa, &send2_sa, send2_salen);
        *ret_send2_salen = send2_salen;

        return 0;

fail:
        if (recv_fd >= 0)
                (void) close(recv_fd);
        if (send1_fd >= 0)
                (void) close(send1_fd);
        if (send2_fd >= 0)
                (void) close(send2_fd);
        if (socket_bound)
                (void) unlink(recv_sa.un.sun_path);
        if (directory_made)
                (void) rmdir(directory);

        return r;
}

static void sigchld(int sig) {}

static int move_fd_up(int *fd) {
        int moved;

        assert(fd);

        if (*fd >= 3)
                return 0;

        moved = fcntl(*fd, F_DUPFD_CLOEXEC, 3);
        if (moved < 0)
                return -errno;

        (void) close(*fd);
        *fd = moved;

        return 0;
}

static int go(char *const *cmdline) {

        bool dead = false, old_ss_valid = false, old_sa_valid = false;
        int recv_fd = -1, send1_fd = -1, send2_fd = -1, r;
        union sockaddr_union send1_sa, send2_sa;
        socklen_t send1_salen, send2_salen;
        struct sigaction old_sa, new_sa = {
                .sa_handler = sigchld,
                .sa_flags = SA_NOCLDSTOP,
        };
        size_t buffer_size = 4096;
        sigset_t new_ss, old_ss;
        void *buffer = NULL;
        pid_t child_pid = 0;
        siginfo_t si;

        assert(cmdline);
        assert(cmdline[0]); /* at least one argument before NULL */

        if (sigaction(SIGCHLD, &new_sa, &old_sa) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to set up SIGCHLD handler: %m");
                goto finish;
        }

        old_sa_valid = true;

        if (sigemptyset(&new_ss) < 0 ||
            sigaddset(&new_ss, SIGCHLD) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to initialize signal mask: %m");
                goto finish;
        }

        if (sigprocmask(SIG_BLOCK, &new_ss, &old_ss) < 0) {
                r = -errno;
                fprintf(stderr, "Failed to set up new signal mask: %m");
                goto finish;
        }

        old_ss_valid = true;

        r = allocate_sockets(&recv_fd, &send1_fd, &send2_fd, &send1_sa, &send1_salen, &send2_sa, &send2_salen);
        if (r < 0)
                goto finish;

        child_pid = fork();
        if (child_pid < 0) {
                r = -errno;
                fprintf(stderr, "Failed to fork payload process: %m\n");
                goto finish;
        }
        if (child_pid == 0) { /* Child */
                /* Not strictly necessary, uses O_CLOEXEC anyway */
                (void) close(recv_fd);

                /* First move the two file descriptors out of the stdin/stdout/stderr range in case that's where they
                 * are. (This is unlikely if we got executed with stdin/stdout/stderr properly initialized, as we
                 * should, but let's rather be safe than sorry.)*/
                r = move_fd_up(&send1_fd);
                if (r < 0) {
                        errno = -r;
                        fprintf(stderr, "Failed to move stdout file descriptor up: %m\n");
                        _exit(EXIT_FAILURE);
                }

                r = move_fd_up(&send2_fd);
                if (r < 0) {
                        errno = -r;
                        fprintf(stderr, "Failed to move stderr file descriptor up: %m\n");
                        _exit(EXIT_FAILURE);
                }

                /* Flush out everything before we replace stdout/stderr */
                fflush(stdout);
                fflush(stderr);

                /* And now move them to the right place, turning off O_CLOEXEC */
                if (dup2(send1_fd, STDOUT_FILENO) < 0) {
                        fprintf(stderr, "Failed to move file descriptor to stdout: %m\n");
                        _exit(EXIT_FAILURE);
                }

                if (dup2(send2_fd, STDERR_FILENO) < 0) {
                        fprintf(stderr, "Failed to move file descriptor to stderr: %m\n");
                        _exit(EXIT_FAILURE);
                }

                /* Not strictly necessary, uses O_CLOEXEC anyway */
                (void) close(send1_fd);
                (void) close(send2_fd);

                execvp(cmdline[0], cmdline);
                fprintf(stderr, "Failed to execute '%s': %m\n", cmdline[0]);
                _exit(EXIT_FAILURE);
        }

        (void) close(send1_fd);
        send1_fd = -1;

        (void) close(send2_fd);
        send2_fd = -1;

        for (;;) {
                union sockaddr_union sa;
                struct pollfd pollfd = {
                        .fd = recv_fd,
                        .events = POLLIN,
                };
                socklen_t salen;
                bool is_stderr;
                const void *p;
                ssize_t n;
                size_t l;
                int i;

                if (!dead) {
                        /* Let's see if our child has died */
                        si = (siginfo_t) {};

                        if (waitid(P_PID, child_pid, &si, WNOHANG|WEXITED) < 0) {
                                if (errno != EAGAIN) {
                                        r = -errno;
                                        fprintf(stderr, "Failed to waitid(): %m\n");
                                        goto finish;
                                }
                        } else if (si.si_pid == child_pid)
                                dead = true; /* Yupp, it's dead. */
                }

                if (ppoll(&pollfd, 1, dead ? &(struct timespec) {} : NULL, &old_ss) < 0) {
                        if (errno == EINTR) /* possibly SIGCHLD, let's query waitid() above */
                                continue;

                        r = -errno;
                        fprintf(stderr, "Failed to poll(): %m\n");
                        goto finish;
                }

                if (ioctl(recv_fd, SIOCINQ, &i) < 0) {
                        r = -errno;
                        fprintf(stderr, "Failed to read input buffer size: %m\n");
                        goto finish;
                }

                if ((size_t) i > buffer_size) {
                        /* Grow the buffer if necessary */
                        buffer_size = i;

                        free(buffer);
                        buffer = NULL;
                }

                if (!buffer) {
                        /* We allocate a buffer that can fit in the datagram plus the ANSI intro and outro if we need it */
                        buffer = malloc(strlen(ANSI_RED) + buffer_size + strlen(ANSI_NORMAL));
                        if (!buffer) {
                                fprintf(stderr, "Out of memory: %m\n");
                                goto finish;
                        }
                }

                salen = sizeof(sa);
                n = recvfrom(recv_fd, (uint8_t*) buffer + strlen(ANSI_RED), buffer_size, 0, &sa.sa, &salen);
                if (n < 0) {
                        if (errno == EAGAIN) {
                                if (dead) /* Nothing to read and our child is dead? If so, let's exit */
                                        break;

                                if (pollfd.revents & (POLLHUP|POLLERR)) /* Paranoia */
                                        break;

                                continue;
                        }

                        r = -errno;
                        fprintf(stderr, "Failed to read from socket: %m\n");
                        goto finish;
                }

                /* Distuingish whether this is stderr or stdout by the sending socket address */
                is_stderr = salen == send2_salen && memcmp(&sa, &send2_sa, salen) == 0;

                if (is_stderr) {
                        /* This is stderr traffic, let's prefix it with the ANSI sequences and output this as a whole */
                        memcpy(buffer, ANSI_RED, strlen(ANSI_RED));
                        memcpy((uint8_t*) buffer + strlen(ANSI_RED) + n, ANSI_NORMAL, strlen(ANSI_NORMAL));

                        p = buffer;
                        l = strlen(ANSI_RED) + n + strlen(ANSI_NORMAL);
                } else {
                        /* This is stdout traffic, let's output this without any prefixes the way it is */
                        p = (uint8_t*) buffer + strlen(ANSI_RED);
                        l = n;
                }

                while (l > 0) {
                        n = write(is_stderr ? STDERR_FILENO : STDOUT_FILENO, p, l);
                        if (n < 0) {
                                r = -errno;
                                fprintf(stderr, "Failed to write data: %m\n");
                                goto finish;
                        }

                        p = (const uint8_t*) p + n;
                        l -= n;
                }
        }

        /* Propagate the childs exit status if it makes sense */
        r = dead && si.si_code == CLD_EXITED ? si.si_status : 255;

finish:
        if (recv_fd >= 0)
                (void) close(recv_fd);
        if (send1_fd >= 0)
                (void) close(send1_fd);
        if (send2_fd >= 0)
                (void) close(send2_fd);

        if (old_sa_valid)
                (void) sigaction(SIGCHLD, &old_sa, NULL);
        if (old_ss_valid)
                (void) sigprocmask(SIG_SETMASK, &old_ss, NULL);

        free(buffer);

        return r;
}

int main(int argc, char *argv[]) {
        int ret;

        if (argc < 2) {
                fprintf(stderr, "Not enough arguments, expected at least one.\n");
                return EXIT_FAILURE;
        }

        ret = go(argv + 1);
        if (ret < 0)
                return EXIT_FAILURE;

        return ret;
}
