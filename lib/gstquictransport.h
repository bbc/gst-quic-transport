/*
 * Copyright 2023 British Broadcasting Corporation - Research and Development
 *
 * Author: Sam Hurst <sam.hurst@bbc.co.uk>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the
 * GNU Lesser General Public License Version 2.1 (the "LGPL"), in
 * which case the following provisions apply instead of the ones
 * mentioned above:
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __GST_QUICLIBTRANSPORT_H__
#define __GST_QUICLIBTRANSPORT_H__

#include <gst/gst.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define GST_TYPE_QUICLIB_TRANSPORT_CONTEXT ( \
    gst_quiclib_transport_context_get_type())
G_DECLARE_DERIVABLE_TYPE (GstQuicLibTransportContext,
    gst_quiclib_transport_context, GST, QUICLIB_TRANSPORT_CONTEXT, GstObject);

typedef enum {
  GST_QUICLIB_ERR_OK = 0,
  GST_QUICLIB_ERR_INTERNAL = -10,
  GST_QUICLIB_ERR_OOM = -11,
  GST_QUICLIB_ERR = -100,
  GST_QUICLIB_ERR_STREAM_ID_BLOCKED = -101,
  GST_QUICLIB_ERR_STREAM_DATA_BLOCKED = -102,
  GST_QUICLIB_ERR_STREAM_CLOSED = -103,
  GST_QUICLIB_ERR_CONN_DATA_BLOCKED = -104,
  GST_QUICLIB_ERR_PACKET_NUM_EXHAUSTED = -105,
  GST_QUICLIB_ERR_CONN_CLOSED = -106,
  GST_QUICLIB_ERR_EXTENSION_NOT_SUPPORTED = -200
} GstQuicLibError;

const gchar * gst_quiclib_error_as_string (GstQuicLibError err);

struct _GstQuicLibTransportContextClass {
  GstObjectClass parent_class;

  /* private */
  gpointer _gst_reserved[GST_PADDING];
};

/*
 * TODO: Rename GstQuicLibServerContext to GstQuicLibTransportServer, or
 * rename GstQuicLibTransportConnection to GstQuicLibClientContext to make
 * these consistent
 */
#define GST_TYPE_QUICLIB_SERVER_CONTEXT ( \
    gst_quiclib_server_context_get_type())
G_DECLARE_FINAL_TYPE (GstQuicLibServerContext,
    gst_quiclib_server_context, GST, QUICLIB_SERVER_CONTEXT,
    GstQuicLibTransportContext);

#define GST_TYPE_QUICLIB_TRANSPORT_CONNECTION ( \
    gst_quiclib_transport_connection_get_type())
G_DECLARE_FINAL_TYPE (GstQuicLibTransportConnection,
    gst_quiclib_transport_connection, GST, QUICLIB_TRANSPORT_CONNECTION,
    GstQuicLibTransportContext);

typedef enum _GstQuicLibTransportContextMode {
  QUIC_CTX_NONE,
  QUIC_CTX_SERVER,
  QUIC_CTX_CLIENT
} GstQuicLibTransportContextMode;

GType
gst_quiclib_transport_context_mode_get_type (void);
#define GST_QUICLIB_TRANSPORT_CONTEXT_MODE_TYPE \
  (gst_quiclib_transport_context_mode_get_type ())

GType gst_quiclib_transport_state_get_type (void);
typedef enum _GstQuicLibTransportState {
  QUIC_STATE_NONE, /* Unlikely */
  QUIC_STATE_LISTENING, /* server only */
  QUIC_STATE_INITIAL, /* Initial packet sent, client only */
  QUIC_STATE_HANDSHAKE,
  QUIC_STATE_OPEN,
  QUIC_STATE_HALF_CLOSED,
  QUIC_STATE_CLOSED,
  QUIC_STATE_MAX
} GstQuicLibTransportState;

#define QUICLIB_CLOSE_NO_ERROR 0x0
#define QUICLIB_CLOSE_INTERNAL_ERROR 0x1
#define QUICLIB_CLOSE_CONN_REFUSED 0x2
#define QUICLIB_CLOSE_FLOW_CONTROL_ERROR 0x3
#define QUICLIB_CLOSE_STREAM_LIMIT_ERROR 0x4
#define QUICLIB_CLOSE_STREAM_STATE_ERROR 0x5
#define QUICLIB_CLOSE_FINAL_SIZE_ERROR 0x6
#define QUICLIB_CLOSE_FRAME_ENCODING_ERROR 0x7
#define QUICLIB_CLOSE_TRANSPORT_PARAMETER_ERROR 0x8
#define QUICLIB_CLOSE_CONNECTION_ID_LIMIT_ERROR 0x9
#define QUICLIB_CLOSE_PROTOCOL_VIOLATION 0xa
#define QUICLIB_CLOSE_INVALID_TOKEN 0xb
#define QUICLIB_CLOSE_APPLICATION_ERROR 0xc
#define QUICLIB_CLOSE_CRYPTO_BUFFER_EXCEEDED 0xd
#define QUICLIB_CLOSE_KEY_UPDATE_ERROR 0xe
#define QUICLIB_CLOSE_AEAD_LIMIT_REACHED 0xf
#define QUICLIB_CLOSE_NO_VIABLE_PATH 0x10
#define QUICLIB_CLOSE_CRYPTO_ERROR 0x100
#define QUICLIB_CLOSE_CRYPTO_ERROR_MAX 0x1ff

#define GST_QUICLIB_TRANSPORT_USER gst_quiclib_transport_user_get_type ()
G_DECLARE_INTERFACE (GstQuicLibTransportUser, gst_quiclib_transport_user, \
    QUICLIB, TRANSPORT_USER, GstObject);

struct _GstQuicLibTransportUserInterface {
  GTypeInterface parent;

  gboolean (*test_alpn) (GstQuicLibTransportUser *self,
                         GstQuicLibTransportContext *ctx,
                         GInetSocketAddress *remote, const gchar *alpn_option);

  gboolean (*new_connection) (GstQuicLibTransportUser *self,
                              GstQuicLibTransportContext *ctx,
                              GInetSocketAddress *remote, const gchar *alpn);

  gboolean (*handshake_complete) (GstQuicLibTransportUser *self,
                                  GstQuicLibTransportContext *ctx,
                                  GstQuicLibTransportConnection *conn,
                                  GInetSocketAddress *remote,
                                  const gchar *alpn);

  gboolean (*stream_opened) (GstQuicLibTransportUser *self,
                             GstQuicLibTransportContext *ctx,
                             guint64 stream_id);

  void (*stream_closed) (GstQuicLibTransportUser *self,
                         GstQuicLibTransportContext *ctx, guint64 stream_id);

  void (*stream_data) (GstQuicLibTransportUser *self,
                       GstQuicLibTransportContext *ctx, GstBuffer *buf);

  /*
   * If set, is called when <25%, <10% and no stream credit is remaining, to
   * prompt applications to extend the stream data if they want to. The return
   * value of this callback will extend the stream offset on the indicated
   * stream ID.
   */
  guint64 (*stream_data_left) (GstQuicLibTransportUser *self,
                               GstQuicLibTransportContext *ctx,
                               guint64 stream_id, guint64 remaining);

  void (*stream_ackd) (GstQuicLibTransportUser *self,
                       GstQuicLibTransportContext *ctx, guint64 stream_id,
                       gsize offset, GstBuffer *ackd_buffer);

  void (*datagram_data) (GstQuicLibTransportUser *self,
                         GstQuicLibTransportContext *ctx, GstBuffer *buf);

  void (*datagram_ackd) (GstQuicLibTransportUser *self,
                         GstQuicLibTransportContext *ctx,
                         GstBuffer *ackd_datagram);

  gboolean (*connection_error) (GstQuicLibTransportUser *self,
                                GstQuicLibTransportContext *ctx,
                                guint64 error);

  void (*connection_closed) (GstQuicLibTransportUser *self,
                             GstQuicLibTransportContext *ctx,
                             GInetSocketAddress *remote);
};

GstQuicLibServerContext *
gst_quiclib_transport_server_new (GstQuicLibTransportUser *user,
    const gchar *pkey_location, const gchar *cert_location, const gchar *sni,
    gpointer app_ctx);

gboolean
gst_quiclib_transport_server_listen (GstQuicLibServerContext *server);

GstQuicLibTransportConnection *
gst_quiclib_transport_client_new (GstQuicLibTransportUser *user,
    gpointer app_ctx);

gboolean
gst_quiclib_transport_client_connect (GstQuicLibTransportConnection *conn);

typedef enum _GstQUICMode GstQUICMode;
GstQUICMode
gst_quiclib_transport_get_mode (GstQuicLibTransportContext *ctx);

GstQuicLibTransportState
gst_quiclib_transport_get_state (GstQuicLibTransportContext *ctx);

gpointer
gst_quiclib_transport_get_app_ctx (GstQuicLibTransportContext *ctx);

void
gst_quiclib_transport_set_app_ctx (GstQuicLibTransportContext *ctx,
    gpointer app_ctx);

GSList *
gst_quiclib_transport_get_listening_addrs (GstQuicLibServerContext *server);

GSList *
gst_quiclib_transport_get_acceptable_alpns (GstQuicLibServerContext *server);

GInetSocketAddress *
gst_quiclib_transport_get_local (GstQuicLibTransportConnection *conn);

GInetSocketAddress *
gst_quiclib_transport_get_peer (GstQuicLibTransportConnection *conn);

gboolean
gst_quiclib_transport_disconnect (GstQuicLibTransportConnection *conn,
    gboolean app_error, guint reason);

/*
 * If addrs encompasses all addresses this server is listening on, or if addrs
 * is NULL, then all listening nodes for this server have been closed and this
 * object can be unref'd. This method will return TRUE in that case.
 */
gboolean
gst_quiclib_transport_server_remove_listens (GstQuicLibServerContext *ctx,
    GSList *addrs);

#define GST_QUICLIB_DEFAULT_ADDRESS "0.0.0.0"
#define GST_QUICLIB_DEFAULT_PORT 443
#define GST_QUICLIB_DEFAULT_SNI "localhost"
#define GST_QUICLIB_DEFAULT_ALPN "qrt-h01"
#define GST_QUICLIB_DEFAULT_CERT_LOCATION "cert.pem"
#define GST_QUICLIB_DEFAULT_KEY_LOCATION "priv.pem"
typedef enum {
	GST_QUICLIB_TRUST_MODE_ENFORCE,
	GST_QUICLIB_TRUST_MODE_WARN,
	GST_QUICLIB_TRUST_MODE_LAX
} GstQuicLibTrustMode;
GType
gst_quiclib_trust_mode_get_type (void);
#define GST_QUICLIB_TRUST_MODE_TYPE (gst_quiclib_trust_mode_get_type ())
#define GST_QUICLIB_DEFAULT_TRUST_MODE GST_QUICLIB_TRUST_MODE_LAX
#define GST_QUICLIB_DEFAULT_TLS_EXPORT NULL

gint64
gst_quiclib_transport_open_stream (GstQuicLibTransportConnection *conn,
    gboolean bidirectional, gpointer stream_ctx);

typedef enum _GstQuicLibStreamState GstQuicLibStreamState;

GstQuicLibStreamState
gst_quiclib_transport_stream_state (GstQuicLibTransportConnection *conn,
    guint64 stream_id);

gboolean
gst_quiclib_transport_close_stream (GstQuicLibTransportConnection *conn,
    guint64 stream_id, guint64 error_code);

GstQuicLibError
gst_quiclib_transport_send_buffer (GstQuicLibTransportConnection *conn,
    GstBuffer *buf, ssize_t *bytes_written);

GstQuicLibError
gst_quiclib_transport_send_stream (GstQuicLibTransportConnection *conn,
								   GstBuffer *buf, gint64 stream_id, ssize_t *bytes_written);

typedef guint64 GstQuicLibDatagramTicket;

GstQuicLibError
gst_quiclib_transport_send_datagram (GstQuicLibTransportConnection *conn,
    GstBuffer *buf, GstQuicLibDatagramTicket *ticket, ssize_t *bytes_written);

#define GST_QUICLIB_VARINT_MAX 4611686018427387903
/*
 * TODO: Move the varint set/get functions here
 */

G_END_DECLS

#endif /* __GSTLIB_QUICTRANSPORT_H__ */
