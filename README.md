# rslogd
syslog server written in Rust as an introduction to [mio](https://github.com/tokio-rs/mio) for [Triangle Rustaceans](https://www.meetup.com/triangle-rustaceans/events/mfglwpyzlbjc/) August 2019 Meetup.

Each stage provides a few more features to discuss.

Stage 1
=======
Stage 1 is the initial UDP only version over IPv4 ([RFC 5426](https://tools.ietf.org/html/rfc5426)). It prints a line for each received syslog packet to port 514 but does not decode it. To see Stage 1, use:

```
git checkout stage1
```

Stage 2
=======
Stage 2 adds UDP over IPv6 and adds syslog packet decoding. It supports 3 types of syslog packets:

1. Original BSD syslog ([RFC 3164](https://tools.ietf.org/html/rfc3164))
2. syslog Version 1 ([RFC 5424](https://tools.ietf.org/html/rfc5424))
3. Apple System Logger (asl)

To see Stage 2, use:

```
git checkout stage2
```

Stage 3
=======
Stage 3 adds TCP over IPv4 and IPv6 ([RFC 6587](https://tools.ietf.org/html/rfc6587)). Syslog over TCP shouldn't be used anymore (deprecated in favor of TLS). But adding it as a stage gives us understanding about using mio with TCP.

To see Stage 3, use:

```
git checkout master
```
