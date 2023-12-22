# Core QUIC Transport elements for GStreamer

This repository contains an implementation of QUIC Transport for GStreamer. It 
uses the ngtcp2 library which provides the QUIC transport implementation.

The motivation behind this project was to develop a set of GStreamer plugins to
allow media pipelines to use QUIC transport for signalling and media transport,
such as [RTP-over-QUIC](https://datatracker.ietf.org/doc/draft-ietf-avtcore-rtp-over-quic/),
 [Media-over-QUIC](https://datatracker.ietf.org/group/moq/about/), and
[SIP-over-QUIC](https://datatracker.ietf.org/doc/draft-hurst-sip-quic/).

## Architecture

![A diagram showing the plugin architecture](/docs/GstSipQuic-quic-transport-no-roq-architecture.png)

This repository contains the "core" plugins to enable QUIC transport within a
GStreamer pipeline. These include a "quicsrc" and "quicsink" element for
carrying QUIC transport data into and out of a GStreamer pipeline, which are
intended to be paired with the included "quicdemux" and "quicmux" elements
respectively which expose the QUIC stream and QUIC datagram flows on a series
of dynamically allocated src and sink pads.

The elements in this repository are not that useful on their own, as they are
designed to be augmented by application-specific muxers and demuxers of their
own. Examples of these can be found in the accompanying 
[gst-roq repository](https://github.com/bbc/gst-roq) shown in the above
diagram. These elements implement the IETF RTP-over-QUIC draft.

### Common QUIC transport

The same QUIC transport connection can be shared between multiple "quicsrc" and
"quicsink" elements in a pipeline. As long as the peer properties on each
element match, they will use the same underlying QUIC transport connection.
This way, it is possible to have full bidirectional communication over QUIC
transport.

The plugins acheive this by utilising the same common "quiclib" library. The
`GstQuicLibCommon` class is a singleton instance which checks whether an
existing connection created by another instance of a QUIC element matches. If
no match is found, then it creates a new `GstQuicLibServerContext` or
`GstQuicLibTransportConnection`. If there is a match, then it increments
the refcount on the object and returns that instance.

### Streams

For each bidirectional or unidirectional QUIC stream, the "quicdemux" element
creates a new src pad. The element remembers peers that have previously
linked against those pads and sends an element query to them with
information about those new stream (in order of first to last seen peer
element) and allows downstream elements to declare an interest in a given QUIC
stream.

Similarly, to open a new bidirectional or unidirectional QUIC stream, an
upstream element simply needs to request a new sink pad from the "quicmux"
element. This element then queries its "quicsink" peer and, if there is an
appropriate QUIC connection established, opens a new QUIC stream.

If the QUIC transport connection negotiates it, then there are additional
datagram pads available on both the "quicdemux" and "quicmux" elements for
receiving and sending QUIC datagram payloads.

## Getting started

This project depends on:

- GSstreamer (>=1.20)
- GStreamer-plugins-base (>=1.20)
- GLib w/Gio
- ngtcp2
- QuicTLS (OpenSSL)

This project has only been tested on Linux x86\_64 so far (Ubuntu 22.04 and
Fedora 39).

### Building the dependencies

The following guides will install the QuicTLS and ngtcp2 dependencies somewhere
other than /usr. This is probably helpful, as it's unlikely you'll find QuicTLS
or ngtcp2 in your distribution's package manager, and QuicTLS will likely clash
with your distribution's provided version of OpenSSL.

For this to work, you should set:
* `$SOME_LOCAL_PREFIX` to your desired install location
* Add `$SOME_LOCAL_PREFIX/bin` to your `$PATH`
* Add`$SOME_LOCAL_PREFIX/lib`, `$SOME_LOCAL_PREFIX/lib64`,
`$SOME_LOCAL_PREFIX/lib/x86_64-linux-gnu` and
`$SOME_LOCAL_PREFIX/lib/x86_64-linux-gnu/gstreamer-1.0` to your
`$LD_LIBRARY_PATH`
* Add `$SOME_LOCAL_PREFIX/lib/x86_64-linux-gnu/pkgconfig`,
`$SOME_LOCAL_PREFIX/lib64/pkgconfig` and `$SOME_LOCAL_PREFIX/lib/pkgconfig` to
your `$PKG_CONFIG_PATH`.

The ngtcp2 project can use multiple SSL backend libraries. It may be possible
to use ngtcp2 with a different SSL back-end than QuicTLS, but this has not been
tested. This project will still require some flavour of OpenSSL to perform
various functions, be it regular OpenSSL, BoringSSL or QuicTLS.

#### QuicTLS

```
$ git clone https://github.com/quictls/openssl
$ cd openssl
$ ./config --prefix=$SOME_LOCAL_PREFIX
$ make
$ make test
$ make install
```

#### ngtcp2

```
$ git clone https://github.com/ngtcp2/ngtcp2
$ cd ngtcp2
$ autoreconf -i
$ ./configure --prefix=$SOME_LOCAL_PREFIX
$ make
$ make install
```

### Building gst-quic-transport

This repository uses the [Meson Build system](https://mesonbuild.com/). As a
quic start guide, the elements and libraries contained in this repository can
be installed using the following commands:

```
meson setup --prefix $SOME_LOCAL_PREFIX build
meson compile -C build
meson install -C build
```

The above commands will create a `build` directory in your source tree, which
is where the compiled objects will be stored before install.
