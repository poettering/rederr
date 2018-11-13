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
