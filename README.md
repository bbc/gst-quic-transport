# Core QUIC Transport elements for GStreamer

This repository contains an implementation of QUIC Transport for GStreamer. It 
uses the ngtcp2 library which provides the QUIC transport implementation.

The motivation behind this project was to develop a set of GStreamer plugins to
allow media pipelines to use QUIC transport for signalling and media transport,
such as [RTP-over-QUIC](https://datatracker.ietf.org/doc/draft-ietf-avtcore-rtp-over-quic/),
 [Media-over-QUIC](https://datatracker.ietf.org/group/moq/about/), and
[SIP-over-QUIC](https://datatracker.ietf.org/doc/draft-hurst-sip-quic/).

## Architecture

```
Insert diagram here
```

This repository contains the "core" plugins to enable QUIC transport within a
GStreamer pipeline. These include a "quicsrc" and "quicsink" element for
carrying QUIC transport data into and out of a GStreamer pipeline, which are
intended to be paired with the included "quicdemux" and "quicmux" elements
respectively which expose the QUIC stream and QUIC datagram flows on a series
of dynamically allocated src and sink pads.

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
