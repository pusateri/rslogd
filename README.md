# rslogd
syslog server written in Rust as an introduction to [mio](https://github.com/tokio-rs/mio) for [Triangle Rustaceans](https://www.meetup.com/triangle-rustaceans/events/mfglwpyzlbjc/) August 2019 Meetup.

Each stage provides a few more features to discuss. To run the syslog server, you'll need to be root or sudo in order to open port 514 and port 601. Use the following commands to build and run:

```
cargo build
sudo target/debug/rslogd  --certs ./my.server.com/cert.pem --key ./my.server.com/privkey.pem
```

Test Commands
=============
For testing over udp, the following clients will work:

```
# Linux
logger -s -i -n 127.0.0.1 testing

# macOS
syslog -s -r 127.0.0.1 testing
```

For testing over TCP, use the following command:

```
# Linux
logger -s -T -P 601 -i -n 127.0.0.1 test TCP message
```

For testing with TLS, use the gnutls-cli command to encapsualte the syslog message:

```
# Linux, FreeBSD, or macOS
gnutls-cli my.server.com --port=6514 --x509cafile=./letsencrypt/letsencryptauthorityx3.pem.txt
```

Then paste in the preformatted syslog line terminating with Ctl-D:

```
<7>May 29 09:20:57 client.example.com syslog[32674]: testing
^D
```

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
git checkout stage3
```

Stage 4
=======
Stage 4 adds TLS over IPv4 support to syslog as described in [RFC 5425](https://tools.ietf.org/html/rfc5425). Adds command line options to provide certificates and private key.

To see Stage 4, use:

```
git checkout stage4
```

Stage 5
=======
Stage 5 adds TLS over IPv6 support and an index pool for tokens.

To see Stage 5, use:

```
git checkout stage5
```
