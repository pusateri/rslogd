# rslogd
syslog server written in Rust as an introduction to mio for Triangle Rustaceans

Each stage provides a few more features to discuss.

Stage 1
=======
Stage 1 is the initial UDP only version over IPv4 (RFC 5426). It prints a line for each received syslog packet to port 514 but does not decode it. To see Stage 1, use:

```
git checkout stage1
```

