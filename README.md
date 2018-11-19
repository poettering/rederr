# rederr

`rederr` is a small tool that invokes another command and propagates its stdout as-is and its stderr in ANSI red.

Just prefix any command line of your choice with `rederr` and it will make it easy for to figure out what is error and what is output.

Example:

```console
# cat > test.sh <<EOF
#!/bin/sh

echo "This is going to stdout"
echo "And this is going to stderr" >&2
EOF

# rederr test.sh
This is going to stdout
And this is going to stderr
```

And yeah, GitHub-style Markdown doesn't really allow for colours. Let's just say the last line in the above output is now red.

## Building:

First ensure you have the `meson` and `ninja` binaries installed, as well as the
required C compiler (`gcc`) and related tools.

Run `meson build` in the project root directory.
Next change into the build directory with `cd build/`
Finally run `ninja` in that directory.
You should now have a `rederr` binary which you can copy to your `$PATH`.

Example:

```console
james@computer:~/code/src/rederr$ meson build
The Meson build system
Version: 0.47.2
Source dir: /home/james/code/src/rederr
Build dir: /home/james/code/src/rederr/build
Build type: native build
Project name: rederr
Project version: 1
Native C compiler: cc (gcc 8.2.1 "cc (GCC) 8.2.1 20181105 (Red Hat 8.2.1-5)")
Build machine cpu family: x86_64
Build machine cpu: x86_64
Build targets in project: 1
Found ninja-1.8.2 at /usr/bin/ninja
james@computer:~/code/src/rederr$ cd build/
james@computer:~/code/src/rederr/build$ ninja
[2/2] Linking target rederr.
james@computer:~/code/src/rederr/build$ file rederr
rederr: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=904987c76a525afd91777107193a564aa2a8cbc4, with debug_info, not stripped
```
