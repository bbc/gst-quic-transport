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

#include "gstquictransport.h"
#include "gstquicstream.h"
#include "gstquicdatagram.h"
#include "gstquiccommon.h"
/*#include "gstquicsignals.h"*/
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

#include <gio/gsocketaddress.h>
#include <gst/net/gstnetaddressmeta.h>
#include <glib/gtypes.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <gobject/gtype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

GST_DEBUG_CATEGORY_STATIC (quiclib_transport);  // define category (statically)
#define GST_CAT_DEFAULT quiclib_transport       // set as default

#define QUICLIB_PARENT(o) g_type_class_peek_parent (o)

#define OPENSSL_DEBUG

const gchar *
gst_quiclib_error_as_string (GstQuicLibError err)
{
  switch (err) {
    case GST_QUICLIB_ERR: return "Generic Error";
    case GST_QUICLIB_ERR_STREAM_ID_BLOCKED: return "Stream ID Blocked";
    case GST_QUICLIB_ERR_STREAM_DATA_BLOCKED: return "Stream Data Blocked";
    case GST_QUICLIB_ERR_STREAM_CLOSED: return "Stream Closed";
    case GST_QUICLIB_ERR_CONN_DATA_BLOCKED: return "Connection Data Blocked";
    case GST_QUICLIB_ERR_PACKET_NUM_EXHAUSTED:
      return "Packet Number Space Exhausted";
  }

  return "Unknown Error";
}

GType
gst_quiclib_trust_mode_get_type (void)
{
  static gsize g_type = 0;
  static const GEnumValue quiclib_trust_mode_types [] = {
      {GST_QUICLIB_TRUST_MODE_ENFORCE, "Enforce certificate checking",
          "Enforce"},
          {GST_QUICLIB_TRUST_MODE_WARN, "Warn on bad certificates", "Warn"},
          {GST_QUICLIB_TRUST_MODE_LAX, "Ignore certificate checking", "Lax"},
          {0, NULL, NULL}
  };

  if (g_once_init_enter (&g_type)) {
    const GType type = g_enum_register_static ("GstQuicLibTrustMode",
        quiclib_trust_mode_types);
    g_once_init_leave (&g_type, type);
  }

  return g_type;
}

GType
gst_quiclib_transport_state_get_type (void)
{
  static gsize g_type = 0;
  static const GEnumValue quiclib_transport_states [] = {
      {QUIC_STATE_NONE, "Invalid state", "None"},
      {QUIC_STATE_LISTENING, "Server listening for connections", "Listening"},
      {QUIC_STATE_INITIAL, "Client INITIAL packet sent", "Initial"},
      {QUIC_STATE_HANDSHAKE, "In Handshake", "Handshake"},
      {QUIC_STATE_OPEN, "Connection Open", "Open"},
      {QUIC_STATE_HALF_CLOSED, "Connection in closing state", "Half closed"},
      {QUIC_STATE_CLOSED, "Connection is closed", "Closed"},
      {0, NULL, NULL}
  };

  if (g_once_init_enter (&g_type)) {
    const GType type = g_enum_register_static ("GstQuicLibTransportState",
        quiclib_transport_states);
    g_once_init_leave (&g_type, type);
  }

  return g_type;
}

#define SOCKET_CONTROL_MESSAGE_ECN_TYPE socket_control_message_ecn_get_type ()
G_DECLARE_FINAL_TYPE (SocketControlMessageECN, socket_control_message_ecn,
    SOCKET_CONTROL_MESSAGE, ECN, GSocketControlMessage);

struct _SocketControlMessageECN {
  GSocketControlMessage parent;

  enum {
    ECN_NOT_ECT = 0,
    ECN_ECT_1,
    ECN_ECT_0,
    ECN_ECT_CE
  } ecn;
};

G_DEFINE_TYPE (SocketControlMessageECN, socket_control_message_ecn,
    G_TYPE_SOCKET_CONTROL_MESSAGE);

static void socket_control_message_ecn_set_property (GObject *object,
    guint prop_id, const GValue *value, GParamSpec *pspec);
static void socket_control_message_ecn_get_property (GObject *object,
    guint prop_id, GValue *value, GParamSpec *pspec);
GSocketControlMessage *socket_control_message_ecn_deserialise (int level,
    int type, gsize size, gpointer data);

enum {
  PROP_ECN_0,
  PROP_ECN_ECN,
};

static void
socket_control_message_ecn_class_init (SocketControlMessageECNClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GSocketControlMessageClass *scmclass = G_SOCKET_CONTROL_MESSAGE_CLASS (klass);

  gobject_class->set_property = socket_control_message_ecn_set_property;
  gobject_class->get_property = socket_control_message_ecn_get_property;
  scmclass->deserialize = socket_control_message_ecn_deserialise;

  g_object_class_install_property (gobject_class, PROP_ECN_ECN,
      g_param_spec_uint ("ecn", "ECN", "Explicit Congestion Notification mark",
          ECN_NOT_ECT, ECN_ECT_CE, ECN_NOT_ECT,
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
socket_control_message_ecn_init (SocketControlMessageECN *ecnscm)
{
  ecnscm->ecn = ECN_NOT_ECT;
}

static void
socket_control_message_ecn_set_property (GObject *object, guint prop_id,
    const GValue *value, GParamSpec *pspec)
{
  SocketControlMessageECN *ecnscm = SOCKET_CONTROL_MESSAGE_ECN (object);

  switch (prop_id) {
    case PROP_ECN_ECN:
      guint32 ecn = g_value_get_uint (value);

      g_return_if_fail (ecn >= ECN_NOT_ECT || ecn <= ECN_ECT_CE);

      ecnscm->ecn = ecn;
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
  }
}

static void
socket_control_message_ecn_get_property (GObject *object, guint prop_id,
    GValue *value, GParamSpec *pspec)
{
  SocketControlMessageECN *ecnscm = SOCKET_CONTROL_MESSAGE_ECN (object);

  switch (prop_id) {
    case PROP_ECN_ECN:
      g_value_set_uint (value, ecnscm->ecn);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
  }
}

GSocketControlMessage *
socket_control_message_ecn_deserialise (int level, int type, gsize size,
    gpointer data)
{
  if ((level == IPPROTO_IP && type == IP_TOS) ||
      (level == IPPROTO_IPV6 && type == IPV6_TCLASS)) {
    guint8 ecn_mark = *(guint8 *) data;

    g_return_val_if_fail (ecn_mark >= ECN_NOT_ECT || ecn_mark <= ECN_ECT_CE,
        NULL);

    return g_object_new (SOCKET_CONTROL_MESSAGE_ECN_TYPE,
        "ecn", (guint) ecn_mark, NULL);
  }

  return NULL;
}

#define SOCKET_CONTROL_MESSAGE_PKTINFO_TYPE \
  socket_control_message_pktinfo_get_type ()
G_DECLARE_FINAL_TYPE (SocketControlMessagePKTINFO,
    socket_control_message_pktinfo, SOCKET_CONTROL_MESSAGE, PKTINFO,
    GSocketControlMessage);

struct _SocketControlMessagePKTINFO {
  GSocketControlMessage parent;

  guint iface_idx;
  GInetAddress *local_address;
  GInetAddress *destination_address;
};

G_DEFINE_TYPE (SocketControlMessagePKTINFO, socket_control_message_pktinfo,
    G_TYPE_SOCKET_CONTROL_MESSAGE);

static void socket_control_message_pktinfo_finalise (
    SocketControlMessagePKTINFO *pktinfoscm);
static void socket_control_message_pktinfo_set_property (GObject *object,
    guint prop_id, const GValue *value, GParamSpec *pspec);
static void socket_control_message_pktinfo_get_property (GObject *object,
    guint prop_id, GValue *value, GParamSpec *pspec);
GSocketControlMessage *socket_control_message_pktinfo_deserialise (int level,
    int type, gsize size, gpointer data);

enum {
  PROP_PKTINFO_0,
  PROP_PKTINFO_IFACE_INDEX,
  PROP_PKTINFO_LOCAL_ADDRESS_INDEX,
  PROP_PKTINFO_DESTINATION_ADDRESS_INDEX
};

static void
socket_control_message_pktinfo_class_init (SocketControlMessagePKTINFOClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GSocketControlMessageClass *scmclass = G_SOCKET_CONTROL_MESSAGE_CLASS (klass);

  gobject_class->finalize = socket_control_message_pktinfo_finalise;
  gobject_class->set_property = socket_control_message_pktinfo_set_property;
  gobject_class->get_property = socket_control_message_pktinfo_get_property;
  scmclass->deserialize = socket_control_message_pktinfo_deserialise;

  g_object_class_install_property (gobject_class, PROP_PKTINFO_IFACE_INDEX,
      g_param_spec_uint ("iface-idx", "Interface index",
          "Unique index of the interface the packet was received on.",
          0, G_MAXUINT, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class,
      PROP_PKTINFO_LOCAL_ADDRESS_INDEX,
      g_param_spec_object ("local-addr", "Local address",
          "Local address of the packet (IPv4 only)", G_TYPE_INET_ADDRESS,
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class,
      PROP_PKTINFO_DESTINATION_ADDRESS_INDEX,
      g_param_spec_object ("dst-addr", "Header destination address",
          "Destination address in the packet header", G_TYPE_INET_ADDRESS,
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
socket_control_message_pktinfo_init (SocketControlMessagePKTINFO *pktinfoscm)
{
  pktinfoscm->iface_idx = 0;
  pktinfoscm->local_address = NULL;
  pktinfoscm->destination_address = NULL;
}

static void
socket_control_message_pktinfo_finalise (
    SocketControlMessagePKTINFO *pktinfoscm)
{
  if (pktinfoscm->local_address) g_object_unref (pktinfoscm->local_address);
  if (pktinfoscm->destination_address)
    g_object_unref (pktinfoscm->destination_address);
}

static void
socket_control_message_pktinfo_set_property (GObject *object, guint prop_id,
    const GValue *value, GParamSpec *pspec)
{
  SocketControlMessagePKTINFO *pktinfoscm =
      SOCKET_CONTROL_MESSAGE_PKTINFO (object);

  switch (prop_id) {
    case PROP_PKTINFO_IFACE_INDEX:
      pktinfoscm->iface_idx = g_value_get_uint (value);
      break;
    case PROP_PKTINFO_LOCAL_ADDRESS_INDEX:
      pktinfoscm->local_address = g_object_ref (g_value_get_object (value));
      break;
    case PROP_PKTINFO_DESTINATION_ADDRESS_INDEX:
      pktinfoscm->destination_address =
          g_object_ref (g_value_get_object (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
  }
}

static void
socket_control_message_pktinfo_get_property (GObject *object, guint prop_id,
    GValue *value, GParamSpec *pspec)
{
  SocketControlMessagePKTINFO *pktinfoscm =
      SOCKET_CONTROL_MESSAGE_PKTINFO (object);

  switch (prop_id) {
  case PROP_PKTINFO_IFACE_INDEX:
    g_value_set_uint (value, pktinfoscm->iface_idx);
    break;
  case PROP_PKTINFO_LOCAL_ADDRESS_INDEX:
    g_value_set_object (value, pktinfoscm->local_address);
    break;
  case PROP_PKTINFO_DESTINATION_ADDRESS_INDEX:
    g_value_set_object (value, pktinfoscm->destination_address);
    break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
  }
}

GSocketControlMessage *
socket_control_message_pktinfo_deserialise (int level, int type, gsize size,
    gpointer data)
{
  GSocketControlMessage *msg = NULL;

  if (level == IPPROTO_IP && type == IP_PKTINFO) {
    struct in_pktinfo *pktinfo;
    GInetAddress *local_addr, *dst_addr;

    g_return_val_if_fail (size == sizeof (struct in_pktinfo), NULL);

    pktinfo = (struct in_pktinfo *) data;

    local_addr = g_inet_address_new_from_bytes (
        (const guint8 *) &pktinfo->ipi_spec_dst, G_SOCKET_FAMILY_IPV4);
    dst_addr = g_inet_address_new_from_bytes (
        (const guint8 *) &pktinfo->ipi_addr, G_SOCKET_FAMILY_IPV4);

    msg = G_SOCKET_CONTROL_MESSAGE (g_object_new (
        SOCKET_CONTROL_MESSAGE_PKTINFO_TYPE, "iface-idx", pktinfo->ipi_ifindex,
        "local-addr", local_addr, "dst-addr", dst_addr, NULL));

    g_object_unref (local_addr);
    g_object_unref (dst_addr);
  } else if  (level == IPPROTO_IPV6 && type == IPV6_PKTINFO) {
    struct in6_pktinfo *pktinfo;
    GInetAddress *dst_addr;

    g_return_val_if_fail (size == sizeof (struct in6_pktinfo), NULL);

    pktinfo = (struct in6_pktinfo *) data;

    dst_addr = g_inet_address_new_from_bytes (
        (const guint8 *) &pktinfo->ipi6_addr, G_SOCKET_FAMILY_IPV6);

    msg = G_SOCKET_CONTROL_MESSAGE (g_object_new (
        SOCKET_CONTROL_MESSAGE_PKTINFO_TYPE, "iface-idx", pktinfo->ipi6_ifindex,
        "dst-addr", dst_addr, NULL));

    g_object_unref (dst_addr);
  }

  return msg;
}

typedef struct _GstQuicLibTransportBufWatchSource {
  GSource parent;

  GMutex mutex;

  GList *bufs;
} GstQuicLibTransportBufWatchSource;

/*
 * TODO: Just use the ngtcp2_transport_params struct instead?
 */
typedef struct _GstQuicLibTransportParameters {
  guint64 max_data;
  guint64 max_stream_data_bidi;
  guint64 max_stream_data_uni;
  guint64 max_streams_bidi;
  guint64 max_streams_uni;
  guint num_cids;
} GstQuicLibTransportParameters;

struct _GstQuicLibTransportContextPrivate {
  GstQuicLibTransportUser *user; /* TODO: Rename to owner? */
  gpointer app_ctx;
  GMainLoop *loop;
  GMainContext *loop_context;
  GThread *loop_thread;
  GSource *timeout;
  guint timeout_id;
  GSocketService *socket_serv;
  GstQuicLibTransportState state;

  gchar *location;

  GstQuicLibTransportParameters tp_sent;

  GRecMutex rmutex;
};

typedef struct _GstQuicLibTransportContextPrivate
GstQuicLibTransportContextPrivate;
G_DEFINE_TYPE_WITH_PRIVATE (GstQuicLibTransportContext,
    gst_quiclib_transport_context, GST_TYPE_OBJECT);

enum {
  PROP_0,
  PROP_TRANSPORT_CONTEXT_USER,
  PROP_TRANSPORT_CONTEXT_APP_CTX,
  PROP_TRANSPORT_CONTEXT_LOOP,
  PROP_TRANSPORT_CONTEXT_DEFAULT_NUM_CIDS,
  PROP_QUIC_ENDPOINT_ENUMS
};

#define NUM_CIDS 4

void
gst_quiclib_transport_connection_get_local_transport_param (
    GstQuicLibTransportContext * ctx, guint prop_id, GValue * value);

gpointer
quiclib_transport_context_loop_thread (gpointer user_data)
{
  GstQuicLibTransportContextPrivate *priv =
      (GstQuicLibTransportContextPrivate *) (user_data);

  g_main_loop_run (priv->loop);

  return NULL;
}

static void gst_quiclib_transport_context_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec);
static void gst_quiclib_transport_context_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec);

void
gst_quiclib_transport_context_class_init (
    GstQuicLibTransportContextClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = gst_quiclib_transport_context_get_property;
  gobject_class->set_property = gst_quiclib_transport_context_set_property;

  g_object_class_install_property (gobject_class, PROP_TRANSPORT_CONTEXT_USER,
      g_param_spec_pointer ("user", "User",
          "Pointer to a class implementing GstQuicLibTransportUserInterface",
          G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class,
      PROP_TRANSPORT_CONTEXT_APP_CTX,
      g_param_spec_pointer ("app_ctx", "Application context",
          "Arbitrary app context associated with this transport context",
          G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_TRANSPORT_CONTEXT_LOOP,
      g_param_spec_pointer ("loop", "GMainLoop",
          "The GMainLoop to be used by this transport context",
          G_PARAM_READWRITE));

  gst_quiclib_common_install_location_property (gobject_class);
  gst_quiclib_common_install_max_data_local_property (gobject_class);
  gst_quiclib_common_install_max_data_remote_property (gobject_class);
  gst_quiclib_common_install_max_stream_data_bidi_local_property (gobject_class);
  gst_quiclib_common_install_max_stream_data_bidi_remote_property (gobject_class);
  gst_quiclib_common_install_max_stream_data_uni_local_property (gobject_class);
  gst_quiclib_common_install_max_stream_data_uni_remote_property (gobject_class);
  gst_quiclib_common_install_max_streams_bidi_local_property (gobject_class);
  gst_quiclib_common_install_max_streams_bidi_remote_property (gobject_class);
  gst_quiclib_common_install_max_streams_uni_local_property (gobject_class);
  gst_quiclib_common_install_max_streams_uni_remote_property (gobject_class);

  g_object_class_install_property (gobject_class,
      PROP_TRANSPORT_CONTEXT_DEFAULT_NUM_CIDS,
      g_param_spec_uint ("default_num_cids", "Default number of CIDs",
          "The default number of CIDs to negotiate for each connection",
          1, G_MAXUINT, NUM_CIDS, G_PARAM_READWRITE));

  g_type_ensure (SOCKET_CONTROL_MESSAGE_ECN_TYPE);
  g_type_ensure (SOCKET_CONTROL_MESSAGE_PKTINFO_TYPE);

  GST_DEBUG_CATEGORY_INIT (quiclib_transport, "quictransport", 0,
      "Base class for QUIC Transport");
}

static void
gst_quiclib_transport_context_init (GstQuicLibTransportContext *self)
{
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (self);
  priv->user = NULL;
  priv->app_ctx = NULL;
  /*
   * Assign the loop and thread only when a socket is ready to be added -
   * allows connections with a server parent to share a loop.
   */
  priv->loop_context = NULL;
  priv->loop = NULL;
  priv->loop_thread = NULL;
  priv->timeout = NULL;
  priv->timeout_id = 0;
  priv->socket_serv = NULL;
  priv->location = g_strdup (QUICLIB_LOCATION_DEFAULT);


  priv->tp_sent.max_data = QUICLIB_MAX_DATA_DEFAULT;
  priv->tp_sent.max_stream_data_bidi = QUICLIB_MAX_STREAM_DATA_DEFAULT;
  priv->tp_sent.max_stream_data_uni = QUICLIB_MAX_STREAM_DATA_DEFAULT;
  priv->tp_sent.max_streams_bidi = QUICLIB_MAX_STREAMS_BIDI_DEFAULT;
  priv->tp_sent.max_streams_uni = QUICLIB_MAX_STREAMS_UNI_DEFAULT;
  priv->tp_sent.num_cids = NUM_CIDS;

  g_rec_mutex_init (&priv->rmutex);
}

static void gst_quiclib_transport_context_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec)
{
  GstQuicLibTransportContext *ctx = GST_QUICLIB_TRANSPORT_CONTEXT (object);
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);

  if (gst_debug_category_get_threshold (quiclib_transport) >= GST_LEVEL_TRACE)
  {
    gchar *valcon = g_strdup_value_contents (value);

    GST_TRACE_OBJECT (ctx, "Setting property %s to %s", pspec->name, valcon);

    g_free (valcon);
  }

  switch (prop_id) {
  case PROP_TRANSPORT_CONTEXT_USER:
    priv->user = g_value_get_pointer (value);
    break;
  case PROP_TRANSPORT_CONTEXT_APP_CTX:
    priv->app_ctx = g_value_get_pointer (value);
    break;
  case PROP_TRANSPORT_CONTEXT_LOOP:
    priv->loop = g_value_get_pointer (value);
    break;
  case PROP_LOCATION:
    if (priv->location) {
      g_free (priv->location);
    }
    priv->location = g_value_dup_string (value);
    break;
  case PROP_MAX_DATA_REMOTE:
    priv->tp_sent.max_data = g_value_get_uint64 (value);
    break;
  case PROP_MAX_STREAM_DATA_BIDI_REMOTE:
    priv->tp_sent.max_stream_data_bidi = g_value_get_uint64 (value);
    break;
  case PROP_MAX_STREAM_DATA_UNI_REMOTE:
    priv->tp_sent.max_stream_data_uni = g_value_get_uint64 (value);
    break;
  case PROP_MAX_STREAMS_BIDI_REMOTE:
    priv->tp_sent.max_streams_bidi = g_value_get_uint64 (value);
    break;
  case PROP_MAX_STREAMS_UNI_REMOTE:
    priv->tp_sent.max_streams_uni = g_value_get_uint64 (value);
    break;
  case PROP_TRANSPORT_CONTEXT_DEFAULT_NUM_CIDS:
    priv->tp_sent.num_cids = g_value_get_uint (value);
    break;
  case PROP_MAX_DATA_LOCAL:
  case PROP_MAX_STREAM_DATA_BIDI_LOCAL:
  case PROP_MAX_STREAM_DATA_UNI_LOCAL:
  case PROP_MAX_STREAMS_BIDI_LOCAL:
  case PROP_MAX_STREAMS_UNI_LOCAL:
    g_critical ("Attempted to set read-only parameter: %s", pspec->name);
    /* no break */
  default:
    G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
  }
}

static void gst_quiclib_transport_context_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec)
{
  GstQuicLibTransportContext *ctx = GST_QUICLIB_TRANSPORT_CONTEXT (object);
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);

  GST_TRACE_OBJECT (ctx, "Get value of property %s", pspec->name);

  switch (prop_id) {
  case PROP_TRANSPORT_CONTEXT_USER:
    g_value_set_pointer (value, priv->user);
    break;
  case PROP_TRANSPORT_CONTEXT_APP_CTX:
    g_value_set_pointer (value, priv->app_ctx);
    break;
  case PROP_TRANSPORT_CONTEXT_LOOP:
    g_value_set_pointer (value, priv->loop);
    break;
  case PROP_LOCATION:
    g_value_set_string (value, priv->location);
    break;
  case PROP_MAX_DATA_LOCAL:
  case PROP_MAX_STREAM_DATA_BIDI_LOCAL:
  case PROP_MAX_STREAM_DATA_UNI_LOCAL:
  case PROP_MAX_STREAMS_BIDI_LOCAL:
  case PROP_MAX_STREAMS_UNI_LOCAL:
    gst_quiclib_transport_connection_get_local_transport_param (ctx, prop_id,
        value);
    break;
  case PROP_MAX_DATA_REMOTE:
    g_value_set_uint64 (value, priv->tp_sent.max_data);
    break;
  case PROP_MAX_STREAM_DATA_BIDI_REMOTE:
    g_value_set_uint64 (value, priv->tp_sent.max_stream_data_bidi);
    break;
  case PROP_MAX_STREAM_DATA_UNI_REMOTE:
    g_value_set_uint64 (value, priv->tp_sent.max_stream_data_uni);
    GST_DEBUG_OBJECT (ctx, "Set initial max_stream_data_uni to %lu",
        priv->tp_sent.max_stream_data_uni);
    break;
  case PROP_MAX_STREAMS_BIDI_REMOTE:
    g_value_set_uint64 (value, priv->tp_sent.max_streams_bidi);
    break;
  case PROP_MAX_STREAMS_UNI_REMOTE:
    g_value_set_uint64 (value, priv->tp_sent.max_streams_uni);
    break;
  case PROP_TRANSPORT_CONTEXT_DEFAULT_NUM_CIDS:
    g_value_set_uint (value, priv->tp_sent.num_cids);
    break;
  default:
    G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
  }
}

/*#define LOCK_DEBUGGING 1*/

void
quiclib_transport_context_lock (GstQuicLibTransportContext *ctx)
{
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);

  g_rec_mutex_lock (&priv->rmutex);
}

#ifndef LOCK_DEBUGGING
#define gst_quiclib_transport_context_lock(c) \
  quiclib_transport_context_lock (GST_QUICLIB_TRANSPORT_CONTEXT (c))
#else
#define gst_quiclib_transport_context_lock(c) \
  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (c), "Locking ngtcp2 lock"); \
  quiclib_transport_context_lock (GST_QUICLIB_TRANSPORT_CONTEXT (c))
#endif

void
quiclib_transport_context_unlock (GstQuicLibTransportContext *ctx)
{
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);

  g_rec_mutex_unlock (&priv->rmutex);
}

#ifndef LOCK_DEBUGGING
#define gst_quiclib_transport_context_unlock(c) \
  quiclib_transport_context_unlock (GST_QUICLIB_TRANSPORT_CONTEXT (c))
#else
#define gst_quiclib_transport_context_unlock(c) \
  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (c), "Unlocking ngtcp2 lock"); \
  quiclib_transport_context_unlock (GST_QUICLIB_TRANSPORT_CONTEXT (c))
#endif

/**
 * Begin getters/setters for parameters in GstQuicLibTransportContextPrivate
 */
GstQuicLibTransportUser *
gst_quiclib_transport_context_get_user (gpointer c) {
  GstQuicLibTransportContext *ctx = GST_QUICLIB_TRANSPORT_CONTEXT (c);
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);
  GstQuicLibTransportUser *user;

  gst_quiclib_transport_context_lock (ctx);
  user = priv->user;
  gst_quiclib_transport_context_unlock (ctx);

  return user;
}

void
gst_quiclib_transport_context_set_user (gpointer c,
    GstQuicLibTransportUser *user) {
  GstQuicLibTransportContextPrivate *p =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (c));

  gst_quiclib_transport_context_lock (c);
  p->user = user;
  gst_quiclib_transport_context_unlock (c);
}

void
gst_quiclib_conn_copy_server_user (GstQuicLibServerContext *server,
    GstQuicLibTransportConnection *conn)
{
  GstQuicLibTransportContextPrivate *server_priv =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (server));
  GstQuicLibTransportContextPrivate *conn_priv =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (conn));

  gst_quiclib_transport_context_lock (server);
  gst_quiclib_transport_context_lock (conn);
  conn_priv->user = server_priv->user;
  gst_quiclib_transport_context_unlock (conn);
  gst_quiclib_transport_context_unlock (server);
}

GstQuicLibTransportUser *
gst_quiclib_transport_context_get_app_ctx (gpointer c) {
  GstQuicLibTransportContext *ctx = GST_QUICLIB_TRANSPORT_CONTEXT (c);
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);
  gpointer app_ctx;

  gst_quiclib_transport_context_lock (ctx);
  app_ctx = priv->app_ctx;
  gst_quiclib_transport_context_unlock (ctx);

  return app_ctx;
}

void
gst_quiclib_transport_context_set_app_ctx (gpointer c, gpointer app_ctx) {
  GstQuicLibTransportContextPrivate *p =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (c));

  gst_quiclib_transport_context_lock (c);
  p->app_ctx = app_ctx;
  gst_quiclib_transport_context_unlock (c);
}

GMainLoop *
gst_quiclib_transport_context_get_loop (gpointer c) {
  GstQuicLibTransportContext *ctx = GST_QUICLIB_TRANSPORT_CONTEXT (c);
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);
  GMainLoop *loop;

  gst_quiclib_transport_context_lock (ctx);
  loop = priv->loop;
  gst_quiclib_transport_context_unlock (ctx);

  return loop;
}

void
gst_quiclib_transport_context_set_loop (gpointer c, GMainLoop *loop) {
  GstQuicLibTransportContextPrivate *p =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (c));

  gst_quiclib_transport_context_lock (c);
  p->loop = loop;
  gst_quiclib_transport_context_unlock (c);
}

GMainContext *
gst_quiclib_transport_context_get_loop_context (gpointer c) {
  GstQuicLibTransportContext *ctx = GST_QUICLIB_TRANSPORT_CONTEXT (c);
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);
  GMainContext *loop_context;

  gst_quiclib_transport_context_lock (ctx);
  loop_context = priv->loop_context;
  gst_quiclib_transport_context_unlock (ctx);

  return loop_context;
}

void
gst_quiclib_transport_context_set_loop_context (gpointer c,
    GMainContext *loop_context) {
  GstQuicLibTransportContextPrivate *p =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (c));

  gst_quiclib_transport_context_lock (c);
  p->loop_context = loop_context;
  gst_quiclib_transport_context_unlock (c);
}


GSource *
gst_quiclib_transport_context_get_timeout (gpointer c) {
  GstQuicLibTransportContext *ctx = GST_QUICLIB_TRANSPORT_CONTEXT (c);
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);
  GSource *timeout;

  gst_quiclib_transport_context_lock (ctx);
  timeout = priv->timeout;
  gst_quiclib_transport_context_unlock (ctx);

  return timeout;
}

/*
 * TODO: Set this to be more of a convenience function? Take a func pointer and
 * a time to wait?
 */
void
gst_quiclib_transport_context_set_timeout (gpointer c, GSource *timeout) {
  GstQuicLibTransportContextPrivate *p =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (c));

  gst_quiclib_transport_context_lock (c);
  p->timeout = timeout;
  gst_quiclib_transport_context_unlock (c);
}

GSocketService *
gst_quiclib_transport_context_get_socket_service (gpointer c) {
  GstQuicLibTransportContext *ctx = GST_QUICLIB_TRANSPORT_CONTEXT (c);
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);
  GSocketService *socket_serv;

  gst_quiclib_transport_context_lock (ctx);
  socket_serv = priv->socket_serv;
  gst_quiclib_transport_context_unlock (ctx);

  return socket_serv;
}

void
gst_quiclib_transport_context_set_socket_service (gpointer c,
    GSocketService *socket_serv) {
  GstQuicLibTransportContextPrivate *p =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (c));

  gst_quiclib_transport_context_lock (c);
  p->socket_serv = socket_serv;
  gst_quiclib_transport_context_unlock (c);
}

void
gst_quiclib_transport_context_set_state (GstQuicLibTransportContext *ctx,
    GstQuicLibTransportState state)
{
  GstQuicLibTransportContextPrivate *p =
        gst_quiclib_transport_context_get_instance_private (ctx);
  p->state = state;
}

/**
 * End getters/setters for parameters in GstQuicLibTransportContextPrivate
 */

void
gst_quiclib_transport_context_kill_thread (GstQuicLibTransportContext *ctx)
{
  GstQuicLibTransportContextPrivate *p =
      gst_quiclib_transport_context_get_instance_private (ctx);

  g_main_loop_quit (p->loop);

  g_main_loop_unref (p->loop);

  g_thread_unref (p->loop_thread);

  g_main_context_unref (p->loop_context);

  p->loop = NULL;
  p->loop_context = NULL;

  p->loop_thread = NULL;
}

#define quiclib

guint64
quiclib_ngtcp2_timestamp (void);

gssize
quiclib_packet_write (GstQuicLibTransportConnection *conn, const gchar *data,
    gsize nwrite, ngtcp2_path_storage *ps);

#define QUICLIB_SERVER(ctx) \
		g_type_check_instance_is_a ((GTypeInstance *) ctx, \
				gst_quiclib_server_context_get_type ())
#define QUICLIB_CLIENT(ctx) \
		g_type_check_instance_is_a ((GTypeInstance *) ctx, \
				gst_quiclib_transport_connection_get_type ())

struct _QuicLibSocketContext {
  GSocket *socket;
  GSource *source;
  GstQuicLibTransportContext *owner;
};
typedef struct _QuicLibSocketContext QuicLibSocketContext;

void
quiclib_socket_context_destroy (gpointer data)
{
  QuicLibSocketContext *ctx = (QuicLibSocketContext *) data;

  GST_INFO_OBJECT (ctx->owner, "Destroying transport context %p", data);

  g_source_destroy (ctx->source);
  g_source_unref (ctx->source);

  g_assert (g_socket_close (ctx->socket, NULL));
  g_object_unref (ctx->socket);

  ctx->source = NULL;
  ctx->socket = NULL;

  g_free (ctx);
}

struct _GstQuicLibServerContext {
  GstQuicLibTransportContext parent;

  GSList *sockets; /* GSList of QuicLibSocketContexts */
  GSList *acceptable_alpns; /* GSList of strings */
  const gchar *cert_file_location;
  const gchar *priv_key_location;
  const gchar *sni_host;

  SSL_CTX *ssl_ctx;

  GList *connections; /* GList of GstQuicLibTransportConnection */
};

G_DEFINE_TYPE (GstQuicLibServerContext, gst_quiclib_server_context,
    GST_TYPE_QUICLIB_TRANSPORT_CONTEXT);

static void gst_quiclib_server_context_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec);
static void gst_quiclib_server_context_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec);

static void
gst_quiclib_server_context_finalise (GstQuicLibServerContext *self);

void
gst_quiclib_server_context_class_init (GstQuicLibServerContextClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = gst_quiclib_server_context_get_property;
  gobject_class->set_property = gst_quiclib_server_context_set_property;
  gobject_class->finalize =
      (GObjectFinalizeFunc) gst_quiclib_server_context_finalise;

  gst_quiclib_common_install_alpn_property (gobject_class);
  gst_quiclib_common_install_privkey_location_property (gobject_class);
  gst_quiclib_common_install_cert_location_property (gobject_class);
  gst_quiclib_common_install_sni_property (gobject_class);
}

static void
gst_quiclib_server_context_init (GstQuicLibServerContext *self)
{
  self->sockets = NULL;
  self->acceptable_alpns = NULL;
  self->cert_file_location = NULL;
  self->priv_key_location = NULL;
  self->sni_host = NULL;
  self->ssl_ctx = NULL;
  self->connections = NULL;
}

static void gst_quiclib_server_context_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec)
{
  GstQuicLibServerContext *server = GST_QUICLIB_SERVER_CONTEXT (object);

  if (gst_debug_category_get_threshold (quiclib_transport) >= GST_LEVEL_TRACE)
  {
    gchar *valcon = g_strdup_value_contents (value);

    GST_TRACE_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (server),
        "Setting property %s to %s", pspec->name, valcon);

    g_free (valcon);
  }

  switch (prop_id) {
    case PROP_ALPN:
    {
      gchar *v, *start = NULL, *v_orig;
      gboolean avoid_whitespace = TRUE;

      if (server->acceptable_alpns) {
        g_slist_free (server->acceptable_alpns);
      }

      v_orig = v = g_value_dup_string (value);

      /* Deserialise the ALPNs into a GList */
      while (v != NULL) {
        if (avoid_whitespace && (*v != ' ' && *v != '\t')) {
          avoid_whitespace = FALSE;
          start = v;
        }

        if (*v == ',' || *v == '\0') {
          server->acceptable_alpns = g_slist_append (server->acceptable_alpns,
              g_strndup (start, v - start));
          avoid_whitespace = TRUE;

          if (*v == '\0') {
            break;
          }
        }

        v++;
      }

      g_free (v_orig);
      break;
    }
    /*
     * TODO: Should it ever be expected that the private key and cert location
     * would change during runtime? Or could these be CONSTRUCT_ONLY?
     */
    case PROP_PRIVKEY_LOCATION:
      if (server->priv_key_location) {
        g_free ((gpointer) server->priv_key_location);
      }
      server->priv_key_location = g_value_dup_string (value);
      break;
    case PROP_CERT_LOCATION:
      if (server->cert_file_location) {
        g_free ((gpointer) server->cert_file_location);
      }
      server->cert_file_location = g_value_dup_string (value);
      break;
    case PROP_SNI:
      if (server->sni_host) {
        g_free ((gpointer) server->sni_host);
      }
      server->sni_host = g_value_dup_string (value);
      break;
    default:
      G_OBJECT_CLASS (gst_quiclib_server_context_parent_class)->
        set_property (object, prop_id, value, pspec);
  }
}

static void gst_quiclib_server_context_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec)
{
  GstQuicLibServerContext *server = GST_QUICLIB_SERVER_CONTEXT (object);

  GST_TRACE_OBJECT (server, "Getting value of property %s", pspec->name);

  switch (prop_id) {
    case PROP_ALPN:
    {
      /* Serialise the list to a string */
      GSList *lptr = server->acceptable_alpns;
      guint i = 0;
      gchar **in;
      gchar *out = NULL;

      in = (gchar **) g_malloc (sizeof (gchar *) *
          (g_slist_length (server->acceptable_alpns) + 1));

      for (; lptr != NULL; lptr = g_slist_next (lptr)) {
        in[i++] = lptr->data;
      }

      in[i] = NULL;

      out = g_strjoinv (", ", in);

      g_value_set_string (value, out);

      if (out) {
        g_free (out);
      }
      break;
    }
    case PROP_PRIVKEY_LOCATION:
      g_value_set_string (value, server->priv_key_location);
      break;
    case PROP_CERT_LOCATION:
      g_value_set_string (value, server->cert_file_location);
      break;
    case PROP_SNI:
      g_value_set_string (value, server->sni_host);
      break;
    default:
      G_OBJECT_CLASS (gst_quiclib_server_context_parent_class)->
        get_property (object, prop_id, value, pspec);
  }
}

static void
gst_quiclib_server_context_finalise (GstQuicLibServerContext *self)
{
  if (self->connections) {
    g_list_free_full (self->connections, g_object_unref);
    self->connections = NULL;
  }

  if (self->sockets) {
    g_slist_free_full (self->sockets, quiclib_socket_context_destroy);
    self->sockets = NULL;
  }

  if (self->acceptable_alpns) {
    g_slist_free_full (self->acceptable_alpns, g_free);
  }

  if (self->ssl_ctx) {
    SSL_CTX_free (self->ssl_ctx);
    self->ssl_ctx = NULL;
  }

  gst_quiclib_transport_context_kill_thread (
        GST_QUICLIB_TRANSPORT_CONTEXT (self));
}

#define QUICLIB_SERVER_CONTEXT_SAFE_CAST(o) \
		(GstQuicLibServerContext *) o; \
		if (GST_QUICLIB_TRANSPORT_CONTEXT (o)->type != QUIC_CTX_SERVER) \
		abort (0);

typedef struct {
  GSource parent;

  GstQuicLibTransportConnection *conn;

  GMutex mutex;

  gsize queue_len;
  GAsyncQueue *queue;
} GstQuicLibTransportSendQueueSource;

typedef struct {
  GSource parent;

  enum {
    CB_HANDSHAKE_COMPLETED,
    CB_STREAM_ACK,
    CB_STREAM_OPEN,
    CB_STREAM_CLOSE,
    CB_STREAM_RESET,
    CB_DATAGRAM_ACK
  } type;

  GstQuicLibTransportConnection *conn;
} GstQuicLibTransportCallbackSource;

typedef struct {
  GstQuicLibTransportCallbackSource source;

  GSocketAddress *peer;
} GstQuicLibTransportHandshakeCompleteCallbackSource;

typedef struct {
  GstQuicLibTransportCallbackSource source;

  guint64 stream_id;
} GstQuicLibTransportStreamIDCallbackSource;

typedef struct {
  GstQuicLibTransportCallbackSource source;

  guint64 stream_id;
  guint64 offset;
} GstQuicLibTransportAckCallbackSource;

struct _GstQuicLibTransportConnection {
  GstQuicLibTransportContext parent;

  GstQuicLibServerContext *server;

  QuicLibSocketContext *socket;
  guint watch_source;

  gsize send_queue_lim;
  GstQuicLibTransportSendQueueSource *send_queue_source;

  gchar *alpn;

  ngtcp2_conn *quic_conn;
  ngtcp2_path_storage path;
  ngtcp2_crypto_conn_ref conn_ref;
  ngtcp2_settings conn_settings;
  ngtcp2_transport_params transport_params;
  ngtcp2_ccerr last_error;

  guint64 datagram_ticket;

  SSL_CTX *ssl_ctx;
  SSL *ssl;

  GList *cids;

  /** GHashTable<gint64 (stream id), GstQuicLibStreamContext> */
  GHashTable *streams;

  /** GHashTable <gint64 (datagram ticket), GstBuffer> */
  GHashTable *datagrams_awaiting_ack;

  /*
   * ngtcp2 doesn't give us this information directly, only local streams
   * remaining
   */
  guint64 bidi_remote_streams_remaining;
  guint64 uni_remote_streams_remaining;

  GMutex mutex;
  GCond cond;
};

struct _GstQuicLibStreamContext {
  GstQuicLibStreamState state;

  GList *ack_bufs;
};

typedef struct _GstQuicLibStreamContext GstQuicLibStreamContext;

G_DEFINE_TYPE (GstQuicLibTransportConnection, gst_quiclib_transport_connection,
    GST_TYPE_QUICLIB_TRANSPORT_CONTEXT);

static void gst_quiclib_transport_connection_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec);
static void gst_quiclib_transport_connection_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec);

static void
gst_quiclib_transport_connection_finalise (
    GstQuicLibTransportConnection *self);

void
gst_quiclib_transport_connection_class_init (
    GstQuicLibTransportConnectionClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  gobject_class->set_property = gst_quiclib_transport_connection_set_property;
  gobject_class->get_property = gst_quiclib_transport_connection_get_property;
  gobject_class->finalize =
      (GObjectFinalizeFunc) gst_quiclib_transport_connection_finalise;

  gst_quiclib_common_install_alpn_property (gobject_class);
  gst_quiclib_common_install_bidi_streams_remaining_local_property (
      gobject_class);
  gst_quiclib_common_install_bidi_streams_remaining_remote_property (
      gobject_class);
  gst_quiclib_common_install_uni_streams_remaining_local_property (
      gobject_class);
  gst_quiclib_common_install_uni_streams_remaining_remote_property (
      gobject_class);
  gst_quiclib_common_install_peer_addresses_property (gobject_class);
  gst_quiclib_common_install_local_addresses_property (gobject_class);
}

static void gst_quiclib_transport_connection_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec)
{
  GstQuicLibTransportConnection *conn =
      GST_QUICLIB_TRANSPORT_CONNECTION (object);


  if (gst_debug_category_get_threshold (quiclib_transport) >= GST_LEVEL_TRACE)
  {
    gchar *valcon = g_strdup_value_contents (value);

    GST_TRACE_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Setting property %s to %s", pspec->name, valcon);

    g_free (valcon);
  }

  g_mutex_lock (&conn->mutex);

  switch (prop_id) {
    case PROP_ALPN:
      if (conn->alpn) {
        g_free (conn->alpn);
      }
      conn->alpn = g_value_dup_string (value);
      break;
    case PROP_BIDI_STREAMS_REMAINING_REMOTE:
    {
      guint64 v = g_value_get_uint64 (value);
      if (v > conn->bidi_remote_streams_remaining) {
        v -= conn->bidi_remote_streams_remaining;
        ngtcp2_conn_extend_max_streams_bidi (conn->quic_conn, v);

        conn->bidi_remote_streams_remaining += v;
      }
      break;
    }
    case PROP_UNI_STREAMS_REMAINING_REMOTE:
    {
      guint v = g_value_get_uint64 (value);
      if (v > conn->uni_remote_streams_remaining) {
        v -= conn->uni_remote_streams_remaining;
        ngtcp2_conn_extend_max_streams_uni (conn->quic_conn, v);

        conn->uni_remote_streams_remaining += v;
      }
      break;
    }
    case PROP_BIDI_STREAMS_REMAINING_LOCAL:
    case PROP_UNI_STREAMS_REMAINING_LOCAL:
    case PROP_PEER_ADDRESSES:
    case PROP_LOCAL_ADDRESSES:
      g_critical ("Attempted to set read-only parameter: %s", pspec->name);
      /* no break */
    default:
      G_OBJECT_CLASS (gst_quiclib_transport_connection_parent_class)
        ->set_property (object, prop_id, value, pspec);
  }

  g_mutex_unlock (&conn->mutex);
}

static void gst_quiclib_transport_connection_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec)
{
  GstQuicLibTransportConnection *conn =
      GST_QUICLIB_TRANSPORT_CONNECTION (object);

  GST_TRACE_OBJECT (conn, "Getting value of property %s", pspec->name);

  g_mutex_lock (&conn->mutex);

  switch (prop_id) {
    case PROP_ALPN:
      g_value_set_string (value, conn->alpn);
      break;
    case PROP_BIDI_STREAMS_REMAINING_LOCAL:
      if (conn->quic_conn) {
        guint64 bidi_left =
            (guint64) ngtcp2_conn_get_streams_bidi_left (conn->quic_conn);

        g_value_set_uint64 (value, bidi_left);
      } else {
        g_value_set_uint64 (value, 0);
      }
      break;
    case PROP_BIDI_STREAMS_REMAINING_REMOTE:
      g_value_set_uint64 (value, conn->bidi_remote_streams_remaining);
      break;
    case PROP_UNI_STREAMS_REMAINING_LOCAL:
      if (conn->quic_conn) {
        guint64 uni_left =
            (guint64) ngtcp2_conn_get_streams_uni_left (conn->quic_conn);
        g_value_set_uint64 (value, uni_left);
      } else {
        g_value_set_uint64 (value, 0);
      }
      break;
    case PROP_UNI_STREAMS_REMAINING_REMOTE:
      g_value_set_uint64 (value, conn->uni_remote_streams_remaining);
      break;
    case PROP_PEER_ADDRESSES:
    {
      ngtcp2_path *path;
      GSocketAddress *sa;
      GList *list = NULL;

      path = ngtcp2_conn_get_path (conn->quic_conn);
      sa = g_socket_address_new_from_native (path->remote.addr,
          path->remote.addrlen);

      list = g_list_append (list, (gpointer) sa);

      g_value_set_boxed (value, list);

      break;
    }
    case PROP_LOCAL_ADDRESSES:
    {
      ngtcp2_path *path;
      GSocketAddress *sa;
      GList *list = NULL;

      path = ngtcp2_conn_get_path (conn->quic_conn);
      sa = g_socket_address_new_from_native (path->local.addr,
          path->local.addrlen);

      list = g_list_append (list, (gpointer) sa);

      g_value_set_boxed (value, list);

      break;
    }
    default:
      G_OBJECT_CLASS (gst_quiclib_transport_connection_parent_class)->
        get_property (object, prop_id, value, pspec);
  }

  g_mutex_unlock (&conn->mutex);
}

void
gst_quiclib_transport_connection_get_local_transport_param (
    GstQuicLibTransportContext * ctx, guint prop_id, GValue * value) {
  GstQuicLibTransportConnection *conn;
  const ngtcp2_transport_params *local_tp;

  if (!GST_IS_QUICLIB_TRANSPORT_CONNECTION (ctx)) {
    g_value_set_uint64 (value, 0);
    return;
  }

  conn = GST_QUICLIB_TRANSPORT_CONNECTION (ctx);

  if (conn->quic_conn == NULL) {
    g_value_set_uint64 (value, 0);
    return;
  }

  local_tp = ngtcp2_conn_get_local_transport_params (conn->quic_conn);

  switch (prop_id) {
    case PROP_MAX_DATA_LOCAL:
      g_value_set_uint64 (value, local_tp->initial_max_data);
      break;
    case PROP_MAX_STREAM_DATA_BIDI_LOCAL:
      g_value_set_uint64 (value, local_tp->initial_max_stream_data_bidi_local);
      break;
    case PROP_MAX_STREAM_DATA_UNI_LOCAL:
      g_value_set_uint64 (value, local_tp->initial_max_stream_data_uni);
      break;
    case PROP_MAX_STREAMS_BIDI_LOCAL:
      g_value_set_uint64 (value, local_tp->initial_max_streams_bidi);
      break;
    case PROP_MAX_STREAMS_UNI_LOCAL:
      g_value_set_uint64 (value, local_tp->initial_max_streams_uni);
      break;
    default:
      g_critical ("Unreachable");
      g_assert (0);
  }
}

gpointer
quiclib_int64_hash_key (gint64 key)
{
  gint64 *p = (gint64 *) g_malloc (sizeof (gint64));
  *p = key;
  return (gpointer) p;
}

void
quiclib_hash_key_destroy (gpointer data)
{
  g_free (data);
}

static void
gst_quiclib_transport_connection_init (GstQuicLibTransportConnection *self)
{
  GValue gv_uint64 = G_VALUE_INIT;
  GValue gv_uint = G_VALUE_INIT;

  g_value_init (&gv_uint64, G_TYPE_UINT64);
  g_value_init (&gv_uint, G_TYPE_UINT);

  self->socket = NULL;
  self->alpn = NULL;
  self->quic_conn = NULL;
  self->conn_ref.user_data = NULL;
  self->datagram_ticket = 0;
  self->ssl_ctx = NULL;
  self->ssl = NULL;
  self->streams = g_hash_table_new_full (g_int64_hash, g_int64_equal,
      quiclib_hash_key_destroy, g_free);
  self->datagrams_awaiting_ack = g_hash_table_new_full (g_int64_hash,
      g_int64_equal, g_free, (GDestroyNotify) gst_buffer_unref);
  ngtcp2_ccerr_default (&self->last_error);
  ngtcp2_transport_params_default (&self->transport_params);

  /*
   * Init to 0, they'll be set to the correct values when the connection is made
   */
  self->bidi_remote_streams_remaining = 0;
  self->uni_remote_streams_remaining = 0;

  g_mutex_init (&self->mutex);
  g_cond_init (&self->cond);
}

static void
gst_quiclib_transport_connection_finalise (GstQuicLibTransportConnection *self)
{
  if (self->quic_conn) {
    gst_quiclib_transport_context_lock (self);
    if (!ngtcp2_conn_in_closing_period (self->quic_conn) &&
        !ngtcp2_conn_in_draining_period (self->quic_conn)) {
      ngtcp2_ssize nwrite;
      ngtcp2_pkt_info pi;
      ngtcp2_path_storage ps;
      guint8 buf[1280];

      ngtcp2_path_storage_zero (&ps);

      nwrite = ngtcp2_conn_write_connection_close (self->quic_conn, &ps.path,
          &pi, buf, sizeof (buf), &self->last_error,
          quiclib_ngtcp2_timestamp());

      if (nwrite < 0) {
        GST_ERROR_OBJECT (self,
            "Couldn't write NGTCP2 CONNECTION_CLOSE frame: %s",
            ngtcp2_strerror ((int) nwrite));
      } else {
        quiclib_packet_write (self, (const gchar *) buf, nwrite, &ps);
      }
    }

    ngtcp2_conn_del (self->quic_conn);

    gst_quiclib_transport_context_unlock (self);

    self->quic_conn = NULL;
  }

  if (!self->server && self->socket) {
    g_source_destroy (self->socket->source);
    g_source_unref (self->socket->source);

    g_object_unref (self->socket->socket);

    g_free (self->socket);
    self->socket = NULL;

    gst_quiclib_transport_context_kill_thread (
        GST_QUICLIB_TRANSPORT_CONTEXT (self));
  }

  if (self->cids) {
    g_list_free_full (self->cids, g_free);
    self->cids = NULL;
  }

  if (self->streams) {
    g_hash_table_destroy (self->streams);
    self->streams = NULL;
  }

  if (self->datagrams_awaiting_ack) {
    g_hash_table_destroy (self->datagrams_awaiting_ack);
    self->datagrams_awaiting_ack = NULL;
  }

  if (self->ssl) {
    SSL_free (self->ssl);
    self->ssl = NULL;
  }

  if (self->ssl_ctx) {
    SSL_CTX_free (self->ssl_ctx);
    self->ssl_ctx = NULL;
  }
}

struct GstQuicLibConnectionID {
  enum {
    TYPE_SCID,
    TYPE_DCID
  } type;
  ngtcp2_cid cid;
};

struct _GstQuicLibDatagramBuffers {
  guint64 datagram_id;
  GstBuffer *buf;
};

typedef struct _GstQuicLibDatagramBuffers GstQuicLibDatagramBuffers;


gint
quiclib_transport_process_packet (GstQuicLibTransportConnection *conn,
    const ngtcp2_pkt_info *pktinfo, uint8_t *pkt, size_t pktlen);

/*
 * ngtcp2 callback declarations
 */

void
quiclib_ngtcp2_print (void *user_data, const char *format, ...);

int
quiclib_ngtcp2_recv_client_initial (ngtcp2_conn *quic_conn,
    const ngtcp2_cid *dcid, void *user_data);

int
quiclib_ngtcp2_handshake_completed (ngtcp2_conn *conn, void *user_data);

int
quiclib_ngtcp2_recv_stream_data (ngtcp2_conn *conn, uint32_t flags,
    int64_t stream_id, uint64_t offset,
    const uint8_t *data, size_t datalen,
    void *user_data, void *stream_user_data);

int
quiclib_ngtcp2_recv_datagram (ngtcp2_conn *conn, uint32_t flags,
    const uint8_t *data, size_t datalen,
    void *user_data);

int
quiclib_ngtcp2_ack_stream (ngtcp2_conn *ngconn, int64_t stream_id,
    uint64_t offset, uint64_t datalen,
    void *user_data, void *stream_user_data);

int
quiclib_ngtcp2_ack_datagram (ngtcp2_conn *quic_conn, uint64_t dgram_id,
    void *user_data);

int
quiclib_ngtcp2_on_stream_open (ngtcp2_conn *quic_conn, int64_t stream_id,
    void *user_data);

int
quiclib_ngtcp2_on_stream_close (ngtcp2_conn *quic_conn, uint32_t flags,
    int64_t stream_id, uint64_t app_error_code,
    void *user_data, void *stream_user_data);

int
quiclib_ngtcp2_on_stream_reset (ngtcp2_conn *quic_conn, int64_t stream_id,
    uint64_t final_size, uint64_t app_error_code, void *user_data,
    void *stream_user_data);

void
quiclib_ngtcp2_rand (uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx);

int
quiclib_ngtcp2_get_new_connection_id (ngtcp2_conn *conn, ngtcp2_cid *cid,
    uint8_t *token, size_t cidlen,
    void *user_data);

int
quiclib_ngtcp2_remove_connection_id (ngtcp2_conn *conn,
    const ngtcp2_cid *cid, void *user_data);

ngtcp2_conn *
quiclib_get_ngtcp2_conn (ngtcp2_crypto_conn_ref *conn_ref);

ngtcp2_callbacks quiclib_ngtcp2_client_callbacks = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_client_initial = NULL,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed = quiclib_ngtcp2_handshake_completed,
    .recv_version_negotiation = NULL,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = quiclib_ngtcp2_recv_stream_data,
    .acked_stream_data_offset = quiclib_ngtcp2_ack_stream,
    .stream_open = quiclib_ngtcp2_on_stream_open,
    .stream_close = quiclib_ngtcp2_on_stream_close,
    .recv_stateless_reset = NULL,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .extend_max_local_streams_bidi = NULL,
    .extend_max_local_streams_uni = NULL,
    .rand = quiclib_ngtcp2_rand,
    .get_new_connection_id = quiclib_ngtcp2_get_new_connection_id,
    .remove_connection_id = quiclib_ngtcp2_remove_connection_id,
    .update_key = ngtcp2_crypto_update_key_cb,
    .path_validation = NULL,
    .select_preferred_addr = NULL,
    .stream_reset = quiclib_ngtcp2_on_stream_reset,
    .extend_max_remote_streams_bidi = NULL,
    .extend_max_remote_streams_uni = NULL,
    .extend_max_stream_data = NULL,
    .dcid_status = NULL,
    .handshake_confirmed = NULL,
    .recv_new_token = NULL,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .recv_datagram = quiclib_ngtcp2_recv_datagram,
    .ack_datagram = quiclib_ngtcp2_ack_datagram,
    .lost_datagram = NULL,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .stream_stop_sending = NULL,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    .recv_rx_key = NULL,
    .recv_tx_key = NULL,
    .tls_early_data_rejected = NULL
};

ngtcp2_callbacks quiclib_ngtcp2_server_callbacks = {
    .client_initial = NULL,
    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed = quiclib_ngtcp2_handshake_completed,
    .recv_version_negotiation = NULL,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = quiclib_ngtcp2_recv_stream_data,
    .acked_stream_data_offset = quiclib_ngtcp2_ack_stream,
    .stream_open = quiclib_ngtcp2_on_stream_open,
    .stream_close = quiclib_ngtcp2_on_stream_close,
    .recv_stateless_reset = NULL,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .extend_max_local_streams_bidi = NULL,
    .extend_max_local_streams_uni = NULL,
    .rand = quiclib_ngtcp2_rand,
    .get_new_connection_id = quiclib_ngtcp2_get_new_connection_id,
    .remove_connection_id = quiclib_ngtcp2_remove_connection_id,
    .update_key = ngtcp2_crypto_update_key_cb,
    .path_validation = NULL,
    .select_preferred_addr = NULL,
    .stream_reset = quiclib_ngtcp2_on_stream_reset,
    .extend_max_remote_streams_bidi = NULL,
    .extend_max_remote_streams_uni = NULL,
    .extend_max_stream_data = NULL,
    .dcid_status = NULL,
    .handshake_confirmed = NULL,
    .recv_new_token = NULL,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .recv_datagram = quiclib_ngtcp2_recv_datagram,
    .ack_datagram = quiclib_ngtcp2_ack_datagram,
    .lost_datagram = NULL,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .stream_stop_sending = NULL,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    .recv_rx_key = NULL,
    .recv_tx_key = NULL,
    .tls_early_data_rejected = NULL
};

#define CID_STR_LEN ((NGTCP2_MAX_CIDLEN * 2) + 1)
#define NIBBLE_TO_HEX(nibble, out) \
		if (nibble > 9) { \
			out = nibble + 87; \
		} else { \
			out = nibble + 48; \
		}

void
hextoascii (uint8_t in, char *out) {
  uint8_t top_nibble = (in & 0xf0) >> 4;
  uint8_t bottom_nibble = in & 0x0f;

  NIBBLE_TO_HEX (top_nibble, out[0]);
  NIBBLE_TO_HEX (bottom_nibble, out[1]);
}

gchar *
quiclib_rawcidtostr (const uint8_t *cid, const size_t cidlen, gchar *buf)
{
  gsize i;

  if (cidlen == 0) {
    sprintf (buf, "(not present)");
    return buf;
  }

  for (i = 0; i < cidlen; i++) {
    hextoascii (cid[i], buf + i * 2);
  }
  buf[i * 2] = 0;
  return buf;
}

gchar *
quiclib_cidtostr (ngtcp2_cid *cid, gchar *buf)
{
  return quiclib_rawcidtostr (cid->data, cid->datalen, buf);
}

/*
 * OpenSSL callback definitions
 */

int
quiclib_ssl_select_proto_cb (SSL *ssl, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg)
{
  unsigned int len = 0;
  /* Limited to 255 according to OpenSSL docs */
  GSList *alpn, *src = NULL;
  unsigned char *client_list;
  int rv;
  ngtcp2_crypto_conn_ref *conn_ref =
      (ngtcp2_crypto_conn_ref *) SSL_get_app_data (ssl);
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) conn_ref->user_data;

  if (conn->server) {
    src = conn->server->acceptable_alpns;
  } else {
    gchar *alpn_str = g_strdup (conn->alpn);
    src = g_slist_append (src, (gpointer) alpn_str);
  }

  alpn = src;
  while (alpn != NULL) {
    len += strlen ((gchar *) alpn->data) + 1;
    alpn = alpn->next;
  }

  client_list = alloca (len);
  alpn = src;
  len = 0;
  while (alpn != NULL) {
    gchar *a = (gchar *) alpn->data;
    client_list[len++] = strlen (a);
    memcpy (client_list + len, a, strlen (a));
    len += strlen (a);
    alpn = alpn->next;
  }

  rv = SSL_select_next_proto ((unsigned char **) out, outlen, in, inlen,
      client_list, len);

  if (rv == OPENSSL_NPN_NEGOTIATED) {
    conn->alpn = g_strndup ((const gchar *) *out, *outlen);
  }

  if (!conn->server) {
    g_free (src->data);
    g_slist_free (src);
  }

  if (rv == OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  }

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Client did not present an acceptable ALPN: %.*s",
      (int) inlen, (char *) in);

  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

#ifdef OPENSSL_DEBUG
void
quiclib_openssl_dbg_cb (int write_p, int version, int content_type,
    const void *bufv, size_t len, SSL *ssl, void *arg)
{
  GstQuicLibTransportContext *ctx = GST_QUICLIB_TRANSPORT_CONTEXT (arg);
  const unsigned char *buf = (const unsigned char *) bufv;

  switch (content_type) {
  case SSL3_RT_HEADER:
    GST_TRACE_OBJECT (ctx, "OpenSSL debugging (%p): %s %s record header,"
        " epoch %d, sequence number %04x%04x%04x", ssl, write_p == 1?"Sent":"Received",
            version == TLS1_3_VERSION?"TLS 1.3":"NOT TLS 1.3", (buf[3] << 8 | buf[4]),
                (buf[5] << 8 | buf[6]), (buf[7] << 8 | buf[8]), (buf[9] << 8 | buf[10]));
    break;
  case SSL3_RT_INNER_CONTENT_TYPE:
  {
    const gchar *ict;
    switch (buf[0]) {
    case SSL3_RT_CHANGE_CIPHER_SPEC:
      ict = "ChangeCipherSpec";
      break;
    case SSL3_RT_ALERT:
      ict = "Alert";
      break;
    case SSL3_RT_HANDSHAKE:
      ict = "Handshake";
      break;
    case SSL3_RT_APPLICATION_DATA:
      ict = "ApplicationData";
      break;
    default:
      ict = "Unknown";
    }

    GST_TRACE_OBJECT (ctx,
        "OpenSSL debugging (%p): %s %s inner content type %s", ssl,
        write_p == 1?"Sent":"Received",
            version == TLS1_3_VERSION?"TLS 1.3":"NOT TLS 1.3", ict);
    break;
  }
  case SSL3_RT_HANDSHAKE:
    GST_TRACE_OBJECT (ctx, "OpenSSL debugging (%p): %s %s handshake", ssl,
        write_p == 1?"Sent":"Received",
            version == TLS1_3_VERSION?"TLS 1.3":"NOT TLS 1.3");
    break;
  case SSL3_RT_CHANGE_CIPHER_SPEC:
    GST_TRACE_OBJECT (ctx, "OpenSSL debugging (%p): %s %s ChangeCipherSpec",
        ssl, write_p == 1?"Sent":"Received",
            version == TLS1_3_VERSION?"TLS 1.3":"NOT TLS 1.3");
    break;
  case SSL3_RT_ALERT:
    GST_TRACE_OBJECT (ctx, "OpenSSL debugging (%p): %s %s Alert: "
        "Level \"%s\", description \"%s\"", ssl,
        write_p == 1?"Sent":"Received",
            version == TLS1_3_VERSION?"TLS 1.3":"NOT TLS 1.3",
                SSL_alert_type_string_long (buf[0] << 8),
                SSL_alert_desc_string_long (buf[1]));
    break;
  default:
    GST_TRACE_OBJECT (ctx,
        "OpenSSL debugging (%p): Unknown %s content type %d", ssl,
        version == TLS1_3_VERSION?"TLS 1.3":"NOT TLS 1.3", content_type);
  }
}
#endif

#if 1
void
quiclib_ssl_keylog_cb (const SSL *ssl, const char *line)
{
  time_t curtime;
  struct tm *curtm;
  size_t sz;
  char filename[PATH_MAX];
  FILE *fp;
  gchar cidstr[CID_STR_LEN];
  ngtcp2_crypto_conn_ref *conn_ref =
      (ngtcp2_crypto_conn_ref *) SSL_get_app_data (ssl);
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) conn_ref->user_data;
  ngtcp2_cid *cid = (ngtcp2_cid *) g_list_first (conn->cids)->data;
  const gchar *tls_export_dir = g_getenv ("GST_QUICLIB_TLS_EXPORT_DIR");

  curtime = time(NULL);
  curtm = localtime (&curtime);

  snprintf (filename, PATH_MAX, "%s/%04d%02d%02d-%02d%02d%02d-%s.keys",
      tls_export_dir, curtm->tm_year + 1900, curtm->tm_mon + 1,
      curtm->tm_mday, curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
      quiclib_cidtostr (cid, cidstr));

  fp = fopen (filename, "ab");
  if (fp == NULL) {
    GST_WARNING_OBJECT (GST_QUICLIB_TRANSPORT_CONNECTION (conn),
        "Couldn't open TLS secrets file %s: %s", filename,
        strerror (errno));
    return;
  }

  sz = fprintf (fp, "%s:\n", line);
  fclose (fp);

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONNECTION (conn),
      "Wrote %ld bytes to TLS secrets file %s", sz, filename);
}

void
quiclib_enable_tls_export (GstQuicLibTransportContext *ctx, SSL *ssl)
{
  const gchar *tls_export_dir = g_getenv ("GST_QUICLIB_TLS_EXPORT_DIR");

  if (tls_export_dir) {
    GStatBuf sb;
    if (g_stat (tls_export_dir, &sb) == -1) {
      if (g_mkdir_with_parents (tls_export_dir, 0700) == -1) {
        GST_WARNING_OBJECT (ctx, "Couldn't create TLS export directory: %s",
            strerror (errno));
        return;
      }
    }

    if (!(sb.st_mode & S_IFDIR)) {
      GST_WARNING_OBJECT (ctx, "TLS export path %s is not a directory",
          tls_export_dir);
    }

    GST_DEBUG_OBJECT (ctx, "Logging TLS secrets for connection to %s",
        tls_export_dir);

    SSL_CTX_set_keylog_callback (SSL_get_SSL_CTX (ssl), quiclib_ssl_keylog_cb);
  }
}
#endif

/*
 * ngtcp2 callback definitions
 */
void
quiclib_ngtcp2_print (void *user_data, const char *format, ...)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  va_list args;
  va_start (args, format);
  gst_debug_log_valist (GST_CAT_DEFAULT, GST_LEVEL_LOG, "ngtcp2",
      conn->server?"server":"client", 0, G_OBJECT (conn), format, args);
  va_end (args);
}

#define ASYNC_CALLBACKS 1

const gchar *
_quiclib_transport_callback_type_to_string (int type) {
  switch (type) {
    case CB_HANDSHAKE_COMPLETED: return "handshake completed";
    case CB_STREAM_ACK: return "stream ACK";
    case CB_STREAM_OPEN: return "stream open";
    case CB_STREAM_CLOSE: return "stream close";
    case CB_STREAM_RESET: return "stream reset";
    case CB_DATAGRAM_ACK: return "datagram ACK";
  }
  return "unknown";
}

static gboolean
_quiclib_transport_callback_source_prepare (GSource *source, gint *timeout)
{
  GstQuicLibTransportCallbackSource *cb_source =
      (GstQuicLibTransportCallbackSource *) source;
  GST_TRACE_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (cb_source->conn),
      "Prepare async callback of type %s",
      _quiclib_transport_callback_type_to_string (cb_source->type));
  return TRUE;
}

static gboolean
_quiclib_transport_callback_source_dispatch (GSource *source, GSourceFunc cb,
    gpointer user_data)
{
  GstQuicLibTransportCallbackSource *cb_source =
      (GstQuicLibTransportCallbackSource *) source;
  GstQuicLibTransportConnection * conn = cb_source->conn;
  GstQuicLibTransportUserInterface *iface = QUICLIB_TRANSPORT_USER_GET_IFACE (
      gst_quiclib_transport_context_get_user (conn));

  GST_TRACE_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Dispatching async callback of type %s",
      _quiclib_transport_callback_type_to_string (cb_source->type));

  switch (cb_source->type) {
    case CB_HANDSHAKE_COMPLETED:
      if (iface->handshake_complete != NULL) {
        GstQuicLibTransportHandshakeCompleteCallbackSource *hc_source =
            (GstQuicLibTransportHandshakeCompleteCallbackSource *) cb_source;
        gboolean rv = iface->handshake_complete (
            gst_quiclib_transport_context_get_user (conn),
            &conn->parent, conn, G_INET_SOCKET_ADDRESS (hc_source->peer),
            conn->alpn);
        g_object_unref (hc_source->peer);
        if (rv == FALSE) {
          GST_WARNING_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
              "Transport user indicated handshake was unacceptable");
          /* TODO: Tear down connection */
        }
      }
      break;
    case CB_STREAM_ACK:
      /* TODO: Implement application buffer acknowledgements */
      GST_FIXME_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "Need to implement app buffer acknowledgements");
      break;
    case CB_STREAM_OPEN:
      if (iface->stream_opened != NULL) {
        GstQuicLibTransportStreamIDCallbackSource *sid_source =
            (GstQuicLibTransportStreamIDCallbackSource *) cb_source;
        if (!iface->stream_opened (gst_quiclib_transport_context_get_user (conn),
            GST_QUICLIB_TRANSPORT_CONTEXT (conn), sid_source->stream_id)) {
          GST_FIXME_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
              "Need to implement closing stream async");
        }
      }
      break;
    case CB_STREAM_CLOSE:
    case CB_STREAM_RESET:
      if (iface->stream_closed != NULL) {
        GstQuicLibTransportStreamIDCallbackSource *sid_source =
            (GstQuicLibTransportStreamIDCallbackSource *) cb_source;
        iface->stream_closed (gst_quiclib_transport_context_get_user (conn),
            GST_QUICLIB_TRANSPORT_CONTEXT (conn), sid_source->stream_id);
      }
      break;
    case CB_DATAGRAM_ACK:
      /* TODO: Implement application buffer acknowledgements */
      GST_FIXME_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "Need to implement app buffer acknowledgements");
      break;
  }

  return FALSE; /* Don't keep this source around after firing */
}

static GSourceFuncs _quiclib_transport_callback_source_funcs = {
    .prepare = _quiclib_transport_callback_source_prepare,
    .check = NULL,
    .dispatch = _quiclib_transport_callback_source_dispatch,
    .finalize = NULL
};

void
_quiclib_transport_run_handshake_complete_callback (
    GstQuicLibTransportConnection *conn, GSocketAddress *sa)
{
  GstQuicLibTransportHandshakeCompleteCallbackSource *hc_source;
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (conn));

  hc_source = (GstQuicLibTransportHandshakeCompleteCallbackSource *)
      g_source_new (&_quiclib_transport_callback_source_funcs,
          sizeof (GstQuicLibTransportHandshakeCompleteCallbackSource));

  hc_source->peer = (GSocketAddress *) g_object_ref (G_OBJECT (sa));
  hc_source->source.type = CB_HANDSHAKE_COMPLETED;
  hc_source->source.conn = conn;

  g_source_attach ((GSource *) hc_source, priv->loop_context);
}

void
_quiclib_transport_run_stream_id_callback (GstQuicLibTransportConnection *conn,
    int type, guint64 stream_id)
{
  GstQuicLibTransportStreamIDCallbackSource *sid_source;
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (conn));

  sid_source = (GstQuicLibTransportStreamIDCallbackSource *)
      g_source_new (&_quiclib_transport_callback_source_funcs,
          sizeof (GstQuicLibTransportStreamIDCallbackSource));

  sid_source->stream_id = stream_id;
  sid_source->source.type = type;
  sid_source->source.conn = conn;

  g_source_attach ((GSource *) sid_source, priv->loop_context);
}

#define _quiclib_transport_run_stream_open_callback(conn, stream_id) \
  _quiclib_transport_run_stream_id_callback (conn, CB_STREAM_OPEN, stream_id)

#define _quiclib_transport_run_stream_close_callback(conn, stream_id) \
  _quiclib_transport_run_stream_id_callback (conn, CB_STREAM_CLOSE, stream_id)

#define _quiclib_transport_run_stream_reset_callback(conn, stream_id) \
  _quiclib_transport_run_stream_id_callback (conn, CB_STREAM_RESET, stream_id)

void
_quiclib_transport_run_ack_callback (GstQuicLibTransportConnection *conn,
    guint64 stream_id, guint64 offset)
{
  GstQuicLibTransportAckCallbackSource *ack_source;
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (conn));

  ack_source = (GstQuicLibTransportAckCallbackSource *)
      g_source_new (&_quiclib_transport_callback_source_funcs,
          sizeof (GstQuicLibTransportAckCallbackSource));

  ack_source->stream_id = stream_id;
  ack_source->offset = offset;
  ack_source->source.type =
      (stream_id > QUICLIB_VARINT_MAX)?(CB_DATAGRAM_ACK):(CB_STREAM_ACK);
  ack_source->source.conn = conn;

  g_source_attach ((GSource *) ack_source, priv->loop_context);
}

int
quiclib_ngtcp2_handshake_completed (ngtcp2_conn *quic_conn, void *user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  GstQuicLibTransportUserInterface *iface =
      QUICLIB_TRANSPORT_USER_GET_IFACE (
          gst_quiclib_transport_context_get_user (conn));
  const ngtcp2_transport_params *remote_params;

  gst_quiclib_transport_context_set_state (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      QUIC_STATE_HANDSHAKE);

  remote_params = ngtcp2_conn_get_remote_transport_params (conn->quic_conn);

  /*
   * TODO: How to deal with early streams? Presumably these aren't accounted
   * for in the remote params. This isn't a massive problem as the current
   * implementation here only opens streams when the handshake is completed, but
   * in the future that might change, or we might interop with someone else who
   * does do early streams.
   */
  conn->bidi_remote_streams_remaining = remote_params->initial_max_streams_bidi;
  conn->uni_remote_streams_remaining = remote_params->initial_max_streams_uni;

  if (conn->alpn == NULL) {
    const unsigned char *negotiated_alpn;
    unsigned int negotiated_alpn_len;

    SSL_get0_alpn_selected (conn->ssl, &negotiated_alpn, &negotiated_alpn_len);

    if (negotiated_alpn == NULL || negotiated_alpn_len == 0) {
      GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "Couldn't get negotiated ALPN from OpenSSL!");
    } else {
      conn->alpn = g_strndup ((gchar *) negotiated_alpn, negotiated_alpn_len);
    }
  }

  if (iface->handshake_complete != NULL) {
    GInetSocketAddress *sa = (GInetSocketAddress *)
	          g_socket_address_new_from_native (conn->path.path.remote.addr,
	              conn->path.path.remote.addrlen);
    gboolean rv = iface->handshake_complete (
        gst_quiclib_transport_context_get_user (conn),
        &conn->parent, conn, sa, conn->alpn);
    g_object_unref (sa);
    if (rv == FALSE) {
      GST_WARNING_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "Transport user indicated handshake was unacceptable");
      return -1;
    }
  }

  gst_quiclib_transport_context_set_state (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        QUIC_STATE_OPEN);

  return 0;
}

int
quiclib_ngtcp2_recv_stream_data (ngtcp2_conn *quic_conn, uint32_t flags,
    int64_t stream_id, uint64_t offset,
    const uint8_t *data, size_t datalen,
    void *user_data, void *stream_user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  GstQuicLibTransportUserInterface *iface =
      QUICLIB_TRANSPORT_USER_GET_IFACE (
          gst_quiclib_transport_context_get_user (conn));
  gboolean fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN)?(TRUE):(FALSE);
  GstBuffer *buffer;

  GST_INFO_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Received %s%lu bytes on stream %ld", (fin)?("final "):(""), datalen,
      stream_id);

  if (fin && datalen == 0) {
    /* Empty buffer that will just carry the meta so as to close the stream */
    buffer = gst_buffer_new ();
  } else {
    buffer = gst_buffer_new_memdup (data, datalen);
  }

  if (buffer == NULL) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Couldn't duplicate memory into a GstBuffer");
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  buffer->pts = GST_CLOCK_TIME_NONE;
  buffer->dts = GST_CLOCK_TIME_NONE;
  buffer->duration = GST_CLOCK_TIME_NONE;
  buffer->offset = offset;
  buffer->offset_end = offset + datalen;

  gst_buffer_add_quiclib_stream_meta (buffer, stream_id, offset, datalen, fin);

  iface->stream_data (gst_quiclib_transport_context_get_user (conn),
      GST_QUICLIB_TRANSPORT_CONTEXT (conn), buffer);

  return 0;
}

int
quiclib_ngtcp2_recv_datagram (ngtcp2_conn *quic_conn, uint32_t flags,
    const uint8_t *data, size_t datalen,
    void *user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  GstQuicLibTransportUserInterface *iface =
      QUICLIB_TRANSPORT_USER_GET_IFACE (
          gst_quiclib_transport_context_get_user (conn));

  GstBuffer *buffer;

  GST_INFO_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Received QUIC datagram of size %lu bytes", datalen);

  buffer = gst_buffer_new_memdup (data, datalen);
  if (buffer == NULL) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Couldn't duplicate memory into a GstBuffer");
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  gst_buffer_add_quiclib_datagram_meta (buffer, datalen);

  iface->datagram_data (gst_quiclib_transport_context_get_user (conn),
      GST_QUICLIB_TRANSPORT_CONTEXT (conn), buffer);
  return 0;
}

int
quiclib_ngtcp2_ack_stream (ngtcp2_conn *quic_conn, int64_t stream_id,
    uint64_t offset, uint64_t datalen,
    void *user_data, void *stream_user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  GstQuicLibStreamContext *stream =
      (GstQuicLibStreamContext *) stream_user_data;
  GstQuicLibTransportUserInterface *iface =
      QUICLIB_TRANSPORT_USER_GET_IFACE (
          gst_quiclib_transport_context_get_user (conn));
  GList *bufs;

  GST_LOG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Received ACK for stream %ld, for %lu bytes at offset %lu", stream_id,
        datalen, offset);

  bufs = g_list_first (stream->ack_bufs);
  while (bufs != NULL) {
    GstBuffer *sent_buf = (GstBuffer *) bufs->data;

    if ((offset + datalen) >=
        (sent_buf->offset + gst_buffer_get_size (sent_buf))) {
      GST_LOG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "Dropping acknowledged buffer for stream %ld, length %lu at offset "
          "%lu", stream_id, gst_buffer_get_size (sent_buf), sent_buf->offset);

      if (iface->stream_ackd) {
        iface->stream_ackd (gst_quiclib_transport_context_get_user (conn),
            GST_QUICLIB_TRANSPORT_CONTEXT (conn), (guint64) stream_id,
            (gsize) offset, sent_buf);
      }

      gst_buffer_unref (sent_buf);
      bufs = stream->ack_bufs = g_list_delete_link (stream->ack_bufs, bufs);
    } else {
      bufs = bufs->next;
    }
  }

  if (stream->state == QUIC_STREAM_CLOSED_BOTH && stream->ack_bufs == NULL) {
    g_free (stream);
  }

  return 0;
}

int
quiclib_ngtcp2_ack_datagram (ngtcp2_conn *quic_conn, uint64_t dgram_id,
    void *user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  GstQuicLibTransportUserInterface *iface =
      QUICLIB_TRANSPORT_USER_GET_IFACE (
          gst_quiclib_transport_context_get_user (conn));

  GST_LOG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Received ACK for datagram %lu", dgram_id);

  if (iface->datagram_ackd) {
    GstBuffer *buf;
    if (!g_hash_table_lookup_extended (conn->datagrams_awaiting_ack, &dgram_id,
        NULL, (gpointer *) &buf)) {
      GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "Couldn't find matching buffer for datagram ticket %lu?", dgram_id);
      return 0;
    }
    iface->datagram_ackd (gst_quiclib_transport_context_get_user (conn),
        GST_QUICLIB_TRANSPORT_CONTEXT (conn), buf);
  }

  g_hash_table_remove (conn->datagrams_awaiting_ack, (gconstpointer) &dgram_id);

  return 0;
}

/**
 * Allocates the local stream context, and will extend the maximum number of
 * streams the remote endpoint can open if required.
 */
gboolean
quiclib_alloc_stream_context (GstQuicLibTransportConnection *conn,
    gint64 stream_id)
{
  gboolean rv;
  GstQuicLibStreamContext *stream = g_new0 (GstQuicLibStreamContext, 1);

  stream->state = QUIC_STREAM_OPEN;
  if ((conn->server && QUICLIB_STREAM_IS_UNI_CLIENT (stream_id)) ||
      QUICLIB_STREAM_IS_UNI_SERVER (stream_id)) {
    stream->state |= QUIC_STREAM_CLOSED_SENDING;
  } else if (QUICLIB_STREAM_IS_UNI (stream_id)) {
    stream->state |= QUIC_STREAM_CLOSED_READING;
  }

  /*
   * If this is a remote stream opening, check whether we need to permit more
   * streams from the peer.
   */
  if ((conn->server && QUICLIB_STREAM_IS_CLIENT_INIT (stream_id)) ||
      (QUICLIB_STREAM_IS_SERVER_INIT (stream_id))) {
    gst_quiclib_transport_context_lock (conn);

    GST_TRACE_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn), "Streams remaining "
        "bidi: %lu, uni: %lu. Max streams bidi: %lu, uni: %lu",
        conn->bidi_remote_streams_remaining, conn->uni_remote_streams_remaining,
        conn->transport_params.initial_max_streams_bidi,
        conn->transport_params.initial_max_streams_uni);

    if (QUICLIB_STREAM_IS_BIDI (stream_id)) {
      if (--conn->bidi_remote_streams_remaining <
          conn->transport_params.initial_max_streams_bidi / 2) {
        ngtcp2_conn_extend_max_streams_bidi (conn->quic_conn,
            conn->transport_params.initial_max_streams_bidi);
        conn->bidi_remote_streams_remaining =
            conn->transport_params.initial_max_streams_bidi;
      }
    } else {
      if (--conn->uni_remote_streams_remaining <
          conn->transport_params.initial_max_streams_uni / 2) {
        ngtcp2_conn_extend_max_streams_uni (conn->quic_conn,
            conn->transport_params.initial_max_streams_uni);
        conn->uni_remote_streams_remaining =
            conn->transport_params.initial_max_streams_uni;
      }
    }
  }

  if (ngtcp2_conn_set_stream_user_data (conn->quic_conn, stream_id, stream)
      != 0) {
    g_free (stream);
    rv = FALSE;
  } else {
    rv = g_hash_table_insert (conn->streams,
        quiclib_int64_hash_key (stream_id), stream);
  }

  gst_quiclib_transport_context_unlock (conn);

  return rv;
}

/**
 * Implements the ngtcp2_stream_open callback. Called when a remote stream is
 * opened by the peer.
 *
 * Sends a stream opened event to the instance owner via callback. If the
 * callback returns FALSE, then the owner rejects the stream and it is not
 * opened.
 */
int
quiclib_ngtcp2_on_stream_open (ngtcp2_conn *quic_conn, int64_t stream_id,
    void *user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  GstQuicLibTransportUserInterface *iface =
      QUICLIB_TRANSPORT_USER_GET_IFACE (
          gst_quiclib_transport_context_get_user (conn));
  gboolean rv = TRUE;

#ifdef ASYNC_CALLBACKS
  _quiclib_transport_run_stream_open_callback (conn, stream_id);
#else
  if (iface->stream_opened != NULL) {
    rv = iface->stream_opened (gst_quiclib_transport_context_get_user (conn),
        GST_QUICLIB_TRANSPORT_CONTEXT (conn), stream_id);
  }
#endif

  if (rv == TRUE) {
    rv = quiclib_alloc_stream_context (conn, stream_id);
  } else {
    GST_WARNING_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "User did not agree to open stream %ld", stream_id);
  }

  return (rv == TRUE)?(0):(NGTCP2_ERR_CALLBACK_FAILURE);
}

/**
 * Implements the ngtcp2_stream_close callback.
 */
int
quiclib_ngtcp2_on_stream_close (ngtcp2_conn *quic_conn, uint32_t flags,
    int64_t stream_id, uint64_t app_error_code,
    void *user_data, void *stream_user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  GstQuicLibStreamContext *stream =
      (GstQuicLibStreamContext *) stream_user_data;
  GstQuicLibTransportUserInterface *iface =
      QUICLIB_TRANSPORT_USER_GET_IFACE (
          gst_quiclib_transport_context_get_user (conn));

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Stream %ld is closed", stream_id);

#ifdef ASYNC_CALLBACKS
  _quiclib_transport_run_stream_close_callback (conn, stream_id);
#else
  if (iface->stream_closed != NULL) {
    iface->stream_closed (gst_quiclib_transport_context_get_user (conn),
        GST_QUICLIB_TRANSPORT_CONTEXT (conn), stream_id);
  }
#endif

  stream->state = QUIC_STREAM_CLOSED_BOTH;
  if (stream->ack_bufs == NULL) {
    g_hash_table_remove (conn->streams, &stream_id);
  }

  return 0;
}

/*
 * Implements the ngtcp2_on_stream_reset callback.
 */
int
quiclib_ngtcp2_on_stream_reset (ngtcp2_conn *quic_conn, int64_t stream_id,
    uint64_t final_size, uint64_t app_error_code, void *user_data,
    void *stream_user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  GstQuicLibStreamContext *stream =
      (GstQuicLibStreamContext *) stream_user_data;
  GstQuicLibTransportUserInterface *iface =
      QUICLIB_TRANSPORT_USER_GET_IFACE (
          gst_quiclib_transport_context_get_user (conn));

  GST_INFO_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Stream %ld was reset after %lu bytes with error code %lu", stream_id,
      final_size, app_error_code);

#ifdef ASYNC_CALLBACKS
  _quiclib_transport_run_stream_reset_callback (conn, stream_id);
#else
  if (iface->stream_closed != NULL) {
    iface->stream_closed (gst_quiclib_transport_context_get_user (conn),
        GST_QUICLIB_TRANSPORT_CONTEXT (conn), stream_id);
  }
#endif

  stream->state = QUIC_STREAM_CLOSED_BOTH;
  if (stream->ack_bufs == NULL) {
    g_hash_table_remove (conn->streams, &stream_id);
    g_free (stream);
  }

  return 0;
}

/**
 * Implements the ngtcp2_rand callback. Simply a wrapper around the OpenSSL
 * RAND_bytes function. The ngtcp2_rand_ctx is ignored (it is never set anyway)
 */
void
quiclib_ngtcp2_rand (uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx)
{
  RAND_bytes (dest, destlen);
}

/**
 * Implements the ngtcp2_get_new_connection_id callback. Uses OpenSSL RAND_bytes
 * to generate new connection IDs and tokens on request.
 */
int
quiclib_ngtcp2_get_new_connection_id (ngtcp2_conn *quic_conn, ngtcp2_cid *cid,
    uint8_t *token, size_t cidlen,
    void *user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  ngtcp2_cid *lcid;

  if (RAND_bytes (cid->data, (int) cidlen) != 1) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Couldn't generate a new CID of length %lu with RAND_bytes: %s",
        cidlen, ERR_error_string (ERR_get_error (), NULL));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (gst_debug_category_get_threshold (quiclib_transport) >= GST_LEVEL_TRACE)
  {
    gchar cid_str[CID_STR_LEN], *sa_str;
    GSocketAddress *sa = g_socket_address_new_from_native (
        (struct sockaddr *) &conn->path.remote_addrbuf,
        sizeof (ngtcp2_sockaddr_union));

    sa_str = g_socket_connectable_to_string (G_SOCKET_CONNECTABLE (sa));

    GST_TRACE_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Generated new CID for peer %s: %s", sa_str,
        quiclib_cidtostr (cid, cid_str));

    g_free (sa_str);
  }

  if (token != NULL &&
      RAND_bytes (token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn), "Couldn't generate a "
        "new stateless reset token of length %d with RAND_bytes: %s",
        NGTCP2_STATELESS_RESET_TOKENLEN,
        ERR_error_string (ERR_get_error (), NULL));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* Make a copy as *cid seems to be allocated on the stack */
  lcid = g_malloc (sizeof (ngtcp2_cid));
  memcpy (lcid->data, cid->data, cid->datalen);
  lcid->datalen = cid->datalen;
  conn->cids = g_list_append (conn->cids, (gpointer) lcid);

  return 0;
}

/**
 * Implements the ngtcp2_remove_connection_id callback. Retires old connection
 * IDs.
 */
int
quiclib_ngtcp2_remove_connection_id (ngtcp2_conn *quic_conn,
    const ngtcp2_cid *cid, void *user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  GList *it;

  for (it = conn->cids; it != NULL; it = it->next) {
    if (((ngtcp2_cid *) it->data)->datalen == cid->datalen &&
        memcmp (((ngtcp2_cid *) it->data)->data, cid->data, cid->datalen) == 0)
    {
      g_free (it->data);
      conn->cids = g_list_remove (conn->cids, it);
    }
  }

  return 0;
}

/*
 * Implements the ngtcp2_crypto_get_conn callback.
 */
ngtcp2_conn *
quiclib_get_ngtcp2_conn (ngtcp2_crypto_conn_ref *conn_ref)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) conn_ref->user_data;
  return conn->quic_conn;
}

/*
 * ngtcp2 callbacks end
 */

/*
 * ngtcp2 utility functions
 */

/**
 * Get the current time in nanoseconds.
 */
guint64
quiclib_ngtcp2_timestamp (void)
{
  struct timespec tp;
  if (clock_gettime (CLOCK_MONOTONIC, &tp) != 0) {
    return UINT64_MAX;
  }
  return (guint64) tp.tv_sec * NGTCP2_SECONDS + (guint64) tp.tv_nsec;
}


gpointer
quiclib_copy_gcharstring (gconstpointer src, gpointer user_data)
{
  const gchar *srcstr = (const gchar *) src;
  gchar *rv = g_malloc (strlen (srcstr) + 1);
  if (rv == NULL) {
    return NULL;
  }
  memcpy (rv, srcstr, strlen (srcstr));
  rv[strlen (srcstr)] = 0;
  return rv;
}

ssize_t
quiclib_ngtcp2_get_stream_window (GstQuicLibTransportConnection *conn,
    int64_t stream_id)
{
  uint64_t cwnd, swnd;

  gst_quiclib_transport_context_lock (conn);

  cwnd = ngtcp2_conn_get_cwnd_left (conn->quic_conn);
  if (stream_id >= 0) {
    swnd = ngtcp2_conn_get_max_stream_data_left (conn->quic_conn,
        stream_id);

    /*g_assert (swnd != 0);*/

    if (cwnd > swnd) {
      cwnd = swnd;
    }
  }

  gst_quiclib_transport_context_unlock (conn);

  return cwnd;
}

gboolean
quiclib_timer_expired (gpointer user_data)
{
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;
  int rv;

  gst_quiclib_transport_context_lock (conn);

  rv = ngtcp2_conn_handle_expiry (conn->quic_conn,
      quiclib_ngtcp2_timestamp ());

  if (rv != 0) {
    gst_quiclib_transport_disconnect (conn, FALSE,
        QUICLIB_CLOSE_INTERNAL_ERROR);
  }

  gst_quiclib_transport_context_unlock (conn);

  return G_SOURCE_REMOVE;
}

/*
 * End ngtcp2 utility functions
 */

void
quiclib_store_stream_ack_refs (GstQuicLibTransportConnection *conn,
    guint64 stream_id, GstBuffer *orig,
    GstBuffer *sent)
{
  GstQuicLibTransportUserInterface *iface =
      QUICLIB_TRANSPORT_USER_GET_IFACE (
          gst_quiclib_transport_context_get_user (conn));
  GstQuicLibStreamContext *stream;

  /*
   * Only bother saving the original buffer if there's actually a callback
   * for the acknowledgement
   */
  if (orig && iface->stream_ackd != NULL) {
    GST_FIXME_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn), "TODO: Stream ACKs");
  }

  g_assert (g_hash_table_lookup_extended (conn->streams, &stream_id, NULL,
      (gpointer *) &stream));

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn), "Storing buf %p",
      sent);

  stream->ack_bufs = g_list_append (stream->ack_bufs, sent);
}

void
quiclib_store_datagram_ack_ref (GstQuicLibTransportConnection *conn,
    guint64 datagram_id, GstBuffer *orig)
{
  GstQuicLibTransportUserInterface *iface =
      QUICLIB_TRANSPORT_USER_GET_IFACE (
          gst_quiclib_transport_context_get_user (conn));
  if (iface->datagram_ackd == NULL) return;

  key = g_malloc (sizeof (gint64));
  *key = datagram_id;

  if (!g_hash_table_insert (conn->datagrams_awaiting_ack, (gpointer) key, 
      (gpointer) gst_buffer_ref (orig))) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Couldn't add datagram buffer to awaiting ack hashtable");
  }
}

gboolean
quiclib_cancel_timer (GstQuicLibTransportContext *ctx)
{
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);

  if (priv->timeout) {
    g_source_destroy (priv->timeout);
    g_source_unref (priv->timeout);
    priv->timeout = NULL;
    return TRUE;
  }
  return FALSE;
}

gboolean
quiclib_set_timer (GstQuicLibTransportContext *ctx, GSourceFunc cb,
    guint msec)
{
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);

  GST_DEBUG_OBJECT (ctx, "Setting %s timer for %u msec",
      (priv->timeout)?("replacement"):("new"), msec);

  quiclib_cancel_timer (ctx);

  priv->timeout = g_timeout_source_new (msec);
  g_source_set_callback (priv->timeout, cb, ctx, NULL);
  g_source_attach (priv->timeout, priv->loop_context);

  return TRUE;
}

gssize
quiclib_packet_write (GstQuicLibTransportConnection *conn, const gchar *data,
    gsize nwrite, ngtcp2_path_storage *ps)
{
  GError *err = NULL;
  gssize written;
  GSocketAddress *gsa = g_socket_address_new_from_native (
      ps->path.remote.addr, ps->path.remote.addrlen);

  g_assert (gsa != NULL);

  written = g_socket_send_to (conn->socket->socket, gsa, data, nwrite, NULL,
      &err);

  if (written < 0 && err != NULL) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "g_socket_send_to failed: %s", err->message);
  } else if (gst_debug_category_get_threshold (quiclib_transport)
      >= GST_LEVEL_DEBUG){
    gchar *peer_addr_str = g_socket_connectable_to_string (
        G_SOCKET_CONNECTABLE (gsa));
    ngtcp2_version_cid vc;
    char dcid_str[CID_STR_LEN], scid_str[CID_STR_LEN];

    ngtcp2_pkt_decode_version_cid (&vc, (const uint8_t *) data, nwrite, 18);

    GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Sent %ld bytes to peer %s with DCID %s and SCID %s", written,
        peer_addr_str, quiclib_rawcidtostr (vc.dcid, vc.dcidlen, dcid_str),
        quiclib_rawcidtostr (vc.scid, vc.scidlen, scid_str));

    g_free (peer_addr_str);
  }

  g_object_unref (gsa);

  return written;
}

ssize_t
quiclib_ngtcp2_conn_write (GstQuicLibTransportConnection *conn,
    gint64 stream_id, ngtcp2_vec *frame, size_t nvec,
    int final, GstBuffer *orig_ref)
{
  ngtcp2_path_storage ps, prev_ps;
  uint32_t flags = 0; /* NGTCP2_WRITE_STREAM_FLAG_MORE */
  ngtcp2_pkt_info pi;
  size_t max_udp_size;
  ngtcp2_ssize nwrite, to_write = 0, pdatalen = 0;
  size_t i;

  GstBuffer *buffer;
  GstMapInfo map;

  gst_quiclib_transport_context_lock (conn);

  if (ngtcp2_conn_in_closing_period (conn->quic_conn) ||
      ngtcp2_conn_in_draining_period (conn->quic_conn)) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Connection closed");
    gst_quiclib_transport_context_unlock (conn);
    return -1;
  }
  ngtcp2_path_storage_zero (&ps);
  ngtcp2_path_storage_zero (&prev_ps);

  max_udp_size = ngtcp2_conn_get_max_tx_udp_payload_size (conn->quic_conn);

  if (final) {
    flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
  }

  buffer = gst_buffer_new_and_alloc (max_udp_size);
  if (buffer == NULL) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Couldn't allocate GstBuffer");
    gst_quiclib_transport_context_unlock (conn);
    return -1;
  }

  gst_buffer_map (buffer, &map, GST_MAP_WRITE);

  GST_LOG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "There are %ld bytes available in the cwnd for stream %ld",
      quiclib_ngtcp2_get_stream_window (conn, stream_id),
      stream_id);

  for (i = 0; i < nvec; i++) {
    to_write += frame[i].len;
  }

  if (gst_debug_category_get_threshold (quiclib_transport) >= GST_LEVEL_TRACE)
  {
    GST_TRACE_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "There are %lu stream buffers to write", nvec);
    for (i = 0; i < nvec; i++) {
      GST_TRACE_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "Buffer %lu has size %lu bytes", i, frame[i].len);
    }
  }

  nwrite = ngtcp2_conn_writev_stream (conn->quic_conn, &ps.path, &pi,
      map.data, map.size, &pdatalen, flags, stream_id,
      (frame != NULL)?(frame):(NULL), (frame != NULL)?(nvec):(0),
          quiclib_ngtcp2_timestamp ());

  gst_quiclib_transport_context_unlock (conn);

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "ngtcp2_conn_writev_stream: nwrite %ld, pdatalen %ld", nwrite, pdatalen);

  if (nwrite <= 0) {
    switch (nwrite) {
    case NGTCP2_ERR_WRITE_MORE:
      GST_LOG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn), "Wrote packet "
          "containing %ld bytes for stream ID %ld, with space remaining in "
          "the same packet.", pdatalen, stream_id);
      g_assert (0);
      break;
    case NGTCP2_ERR_NOMEM:
    case NGTCP2_ERR_INVALID_ARGUMENT:
      return GST_QUICLIB_ERR;
    case NGTCP2_ERR_STREAM_NOT_FOUND:
      return GST_QUICLIB_ERR_STREAM_CLOSED;
    case NGTCP2_ERR_STREAM_SHUT_WR:
      return GST_QUICLIB_ERR_STREAM_CLOSED;
    case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
      return GST_QUICLIB_ERR_PACKET_NUM_EXHAUSTED;
    case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      return GST_QUICLIB_ERR_STREAM_DATA_BLOCKED;;
    default:
      GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "UNKNOWN NGTCP2 RETURN CODE: %ld", nwrite);
      return GST_QUICLIB_ERR;
    }
  }

  g_assert (nwrite <= max_udp_size);

  nwrite = quiclib_packet_write (conn, (const gchar *) map.data, nwrite, &ps);
  if (nwrite < 0) {
    gst_buffer_unmap (buffer, &map);
    return -1;
  }

  gst_buffer_unmap (buffer, &map);

  if (pdatalen == -1) {
    pdatalen = 0;
  }

  return pdatalen;
}

ssize_t
quiclib_ngtcp2_datagram_write (GstQuicLibTransportConnection *conn,
    ngtcp2_vec *frame, size_t nvec)
{
  ngtcp2_path_storage ps, prev_ps;
  uint32_t flags = 0; /* NGTCP2_WRITE_DATAGRAM_FLAG_MORE */
  ngtcp2_pkt_info pi;
  size_t max_udp_size;
  ngtcp2_ssize nwrite;
  gint paccepted = 0;
  guint64 datagram_id = conn->datagram_ticket++;

  GstBuffer *buffer;
  GstMapInfo map;

  gst_quiclib_transport_context_lock (conn);

  if (ngtcp2_conn_in_closing_period (conn->quic_conn) ||
      ngtcp2_conn_in_draining_period (conn->quic_conn)) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Connection closed");
    gst_quiclib_transport_context_unlock (conn);
    return -1;
  }
  ngtcp2_path_storage_zero (&ps);
  ngtcp2_path_storage_zero (&prev_ps);

  max_udp_size = ngtcp2_conn_get_max_tx_udp_payload_size (conn->quic_conn);

  buffer = gst_buffer_new_and_alloc (max_udp_size);
  if (buffer == NULL) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Couldn't allocate GstBuffer");
    gst_quiclib_transport_context_unlock (conn);
    return -1;
  }

  gst_buffer_map (buffer, &map, GST_MAP_WRITE);

  GST_LOG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "There are %ld bytes available in the cwnd",
      ngtcp2_conn_get_cwnd_left (conn->quic_conn));

  nwrite = ngtcp2_conn_writev_datagram (conn->quic_conn, &conn->path.path,
      &pi, (uint8_t *) map.data, map.size, &paccepted, flags, datagram_id,
      frame, nvec, quiclib_ngtcp2_timestamp ());

  gst_quiclib_transport_context_unlock (conn);

  gst_buffer_unmap (buffer, &map);
  if (nwrite > 0) {
    GError *err = NULL;
    gssize written;
    GSocketAddress *gsa = g_socket_address_new_from_native (
        ps.path.remote.addr, ps.path.remote.addrlen);

    g_assert (gsa != NULL);

    written = g_socket_send_to (conn->socket->socket, gsa, (gchar *) map.data,
        map.size, NULL, &err);

    if (written < 0 && err != NULL) {
      GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "g_socket_send_to failed: %s", err->message);
    }

    quiclib_store_datagram_ack_ref (conn, datagram_id, buffer);

    g_object_unref (gsa);
  } else {
    switch (nwrite) {
    case NGTCP2_ERR_WRITE_MORE:
      GST_LOG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn), "Wrote packet for "
          "datagram %ld, with space remaining in the same packet.",
          datagram_id);
      g_assert (0);
      break;
    case NGTCP2_ERR_NOMEM:
    case NGTCP2_ERR_STREAM_NOT_FOUND:
    case NGTCP2_ERR_STREAM_SHUT_WR:
    case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
    case NGTCP2_ERR_INVALID_ARGUMENT:
    case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      GST_LOG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "writev_datagram returned %s", ngtcp2_strerror (nwrite));
      return -1;
    }
  }

  return nwrite;
}

/*void
quiclib_print_ngtcp2_transport_params (GstQuicLibTransportContext *ctx,
    ngtcp2_transport_params *params)*/
#define quiclib_print_ngtcp2_transport_params(ctx, params) \
do { \
  GST_DEBUG_OBJECT (ctx, \
      "Preferred addr %s present, Original DCID %s present, " \
      "Initial SCID %s present, Retry SCID %s present, " \
      "initial_max_stream_data_bidi_local %lu, " \
      "initial_max_stream_data_bidi_remote %lu, " \
      "initial_max_stream_data_uni %lu, initial_max_data %lu, " \
      "initial_max_streams_bidi %lu, initial_max_streams_uni %lu, " \
      "max_idle_timeout %lu, max_udp_payload_size %lu, " \
      "active_connection_id_limit %lu, ack_delay_exponent %lu, " \
      "max_ack_delay %lu, max_datagram_frame_size %lu, " \
      "stateless_reset_token_present %s, disable_active_migration %s,", \
      params.preferred_addr_present?(""):("not"), \
      params.original_dcid_present?(""):("not"), \
      params.initial_scid_present?(""):("not"), \
      params.retry_scid_present?(""):("not"), \
      params.initial_max_stream_data_bidi_local, \
      params.initial_max_stream_data_bidi_remote, \
      params.initial_max_stream_data_uni, params.initial_max_data, \
      params.initial_max_streams_bidi, params.initial_max_streams_uni, \
      params.max_idle_timeout, params.max_udp_payload_size,\
      params.active_connection_id_limit, params.ack_delay_exponent,\
      params.max_ack_delay, params.max_datagram_frame_size, \
      params.stateless_reset_token_present?("SET"):("NOT SET"), \
      params.disable_active_migration?("SET"):("NOT SET")); \
} while (0); \

#define MAX_UDP 65507

GstQuicLibTransportConnection *
gst_quiclib_new_conn_from_server (GstQuicLibServerContext *server)
{
  GstQuicLibTransportConnection *conn;
  GstQuicLibTransportContextPrivate *conn_priv;
  GstQuicLibTransportContextPrivate *server_priv =
      gst_quiclib_transport_context_get_instance_private (
          GST_QUICLIB_TRANSPORT_CONTEXT (server));

  conn = g_object_new (GST_TYPE_QUICLIB_TRANSPORT_CONNECTION, NULL);
  if (!conn) {
    return NULL;
  }

  conn->server = server;
  conn_priv = gst_quiclib_transport_context_get_instance_private (
      GST_QUICLIB_TRANSPORT_CONTEXT (conn));

  gst_quiclib_transport_context_lock (server);
  gst_quiclib_transport_context_lock (conn);

  conn_priv->user = server_priv->user;
  conn_priv->app_ctx = server_priv->app_ctx;
  conn_priv->loop = server_priv->loop;
  conn_priv->loop_context = server_priv->loop_context;
  conn_priv->loop_thread = server_priv->loop_thread;

  conn->transport_params.initial_max_data = server_priv->tp_sent.max_data;
  conn->transport_params.initial_max_stream_data_bidi_local =
      conn->transport_params.initial_max_stream_data_bidi_remote =
          server_priv->tp_sent.max_stream_data_bidi;
  conn->transport_params.initial_max_stream_data_uni =
      server_priv->tp_sent.max_stream_data_uni;
  conn->transport_params.initial_max_streams_bidi =
      server_priv->tp_sent.max_streams_bidi;
  conn->transport_params.initial_max_streams_uni =
      server_priv->tp_sent.max_streams_uni;
  conn->transport_params.active_connection_id_limit =
      server_priv->tp_sent.num_cids;

  quiclib_print_ngtcp2_transport_params (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      conn->transport_params);

  server->connections = g_list_append (server->connections, conn);

  gst_quiclib_transport_context_unlock (conn);
  gst_quiclib_transport_context_unlock (server);

  return conn;
}

gboolean
quiclib_data_received (GSocket *socket, GIOCondition condition,
    gpointer user_data) {
  QuicLibSocketContext *socket_ctx = (QuicLibSocketContext *) user_data;
  gssize bytes_read = 0;
  GError *err = NULL;

  g_return_val_if_fail (socket == socket_ctx->socket, FALSE);

  do {
    GSocketAddress *peer_addr, *local_addr;
    GInputVector ivec;
    guint8 buf[MAX_UDP];
    GSocketControlMessage **msgs;
    gint i, num_msgs, flags = G_SOCKET_MSG_NONE;

    int rv;
    ngtcp2_pkt_info pi;
    ngtcp2_version_cid vc;

    GstQuicLibTransportConnection *conn;

    ivec.buffer = buf;
    ivec.size = MAX_UDP;

    if (!G_IS_OBJECT (socket_ctx->socket)) {
      return FALSE;
    }

    bytes_read = g_socket_receive_message (socket_ctx->socket, &peer_addr,
        &ivec, 1, &msgs, &num_msgs, &flags, NULL, &err);

    if (bytes_read < 0) {
      if (err->code == G_IO_ERROR_WOULD_BLOCK) {
        GST_DEBUG_OBJECT (socket_ctx->owner, "No more data, wait");
        bytes_read = 0;
      } else {
        GST_ERROR_OBJECT (socket_ctx->owner,
            "Couldn't receive UDP message: %s", err->message);
      }
      g_error_free (err);
      err = NULL;
      break;
    }

    for (i = 0; i < num_msgs; i++) {
      if (SOCKET_CONTROL_MESSAGE_IS_ECN (msgs[i])) {
        SocketControlMessageECN *ecn_scm =
            SOCKET_CONTROL_MESSAGE_ECN (msgs [i]);

        pi.ecn = ecn_scm->ecn;
      } else if (SOCKET_CONTROL_MESSAGE_IS_PKTINFO (msgs[i])) {
        SocketControlMessagePKTINFO *pktinfo_scm =
            SOCKET_CONTROL_MESSAGE_PKTINFO (msgs [i]);
        GSocketAddress *sa = g_socket_get_local_address (socket_ctx->socket,
            &err);

        if (sa == NULL) {
          GST_ERROR_OBJECT (socket_ctx->owner, "Couldn't get local address: %s",
              err->message);
        } else {
          local_addr = g_inet_socket_address_new (
              pktinfo_scm->destination_address,
              g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (sa)));

          g_object_unref (sa);
        }
      }

      g_object_unref (msgs[i]);
    }

    if (msgs) g_free (msgs);

    if (local_addr == NULL) {
      local_addr = g_socket_get_local_address (socket_ctx->socket, &err);
    }

    if (local_addr == NULL) {
      GST_ERROR_OBJECT (socket_ctx->owner, "Couldn't get local address: %s",
          err->message);
      g_object_unref (peer_addr);
      break;
    }

    rv = ngtcp2_pkt_decode_version_cid (&vc, buf, bytes_read, 18);
    switch (rv) {
    case 0:
    {
      gchar dcid_str[CID_STR_LEN], scid_str[CID_STR_LEN], *peer_addr_str;
      peer_addr_str = g_socket_connectable_to_string (
          G_SOCKET_CONNECTABLE (peer_addr));
      GST_DEBUG_OBJECT (socket_ctx->owner,
          "Received packet of length %ld with DCID %s, SCID %s from %s",
          bytes_read, quiclib_rawcidtostr (vc.dcid, vc.dcidlen, dcid_str),
          quiclib_rawcidtostr (vc.scid, vc.scidlen, scid_str), peer_addr_str);
      g_free (peer_addr_str);
      break;
    }
    case NGTCP2_ERR_VERSION_NEGOTIATION:
      GST_ERROR_OBJECT (socket_ctx->owner,
          "Need to implement version negotiation!");
      g_assert (0);
      break;
    default:
      GST_WARNING_OBJECT (socket_ctx->owner,
          "Could not decode version and CID from QUIC packet header: %s",
          ngtcp2_strerror (rv));
      continue;
    }

    if (QUICLIB_SERVER (socket_ctx->owner)) {
      GstQuicLibServerContext *server =
          GST_QUICLIB_SERVER_CONTEXT (socket_ctx->owner);
      GList *conn_it = server->connections;
      while (conn_it != NULL) {
        GList *cid = ((GstQuicLibTransportConnection *) conn_it->data)->cids;
        while (cid != NULL) {
          if (((ngtcp2_cid *) cid->data)->datalen == vc.dcidlen) {
            if (memcmp (((ngtcp2_cid *) cid->data)->data, vc.dcid, vc.dcidlen)
                == 0) {
              conn = GST_QUICLIB_TRANSPORT_CONNECTION (conn_it->data);
              break;
            }
          }
          cid = cid->next;
        }
        if (cid) break;

        conn_it = conn_it->next;
      }

      if (conn_it == NULL) {
        ngtcp2_pkt_hd hdr;
        ngtcp2_cid *new_scid, *dcid;
        gchar debug_scid_str[CID_STR_LEN], debug_dcid_str[CID_STR_LEN],
        *debug_remote_addr;


        /*
         * TODO: Support multiple clients
         */
        if (server->connections != NULL) {
          GST_WARNING_OBJECT (socket_ctx->owner,
              "TODO: Support multiple clients on a single server");
          continue;
        }

        rv = ngtcp2_accept (&hdr, buf, bytes_read);
        if (rv != 0) {
          if (rv == NGTCP2_ERR_RETRY) {
            GST_ERROR_OBJECT (socket_ctx->owner, "Need to implement retry!");
            g_assert (0);
          }
          GST_WARNING_OBJECT (socket_ctx->owner,
              "Unexpected packet of length %lu bytes", bytes_read);
          continue;
        }

        g_assert (hdr.type == NGTCP2_PKT_INITIAL);

        conn = gst_quiclib_new_conn_from_server (server);
        if (conn == NULL) {
          GST_ERROR_OBJECT (socket_ctx->owner,
              "Couldn't allocation connection context");
          continue;
        }

        new_scid = g_malloc (sizeof (ngtcp2_cid));
        if (new_scid == NULL) {
          GST_ERROR_OBJECT (socket_ctx->owner,
              "Couldn't allocate space for new SCID");
          g_free (conn);
          continue;
        }

        new_scid->datalen = 18;
        if (RAND_bytes (new_scid->data, new_scid->datalen) != 1) {
          GST_ERROR_OBJECT (socket_ctx->owner, "OpenSSL RAND_bytes failed: %s",
              ERR_error_string (ERR_get_error (), NULL));
          g_free (conn);
          continue;
        }

        dcid = g_malloc (sizeof (ngtcp2_cid));
        if (dcid == NULL) {
          GST_ERROR_OBJECT (socket_ctx->owner,
              "Couldn't allocate space for new DCID");
          g_free (new_scid);
          g_free (conn);
          continue;
        }
        memcpy (dcid->data, hdr.scid.data, hdr.scid.datalen);
        dcid->datalen = hdr.scid.datalen;

        /* TODO: Should this be a copy, and then set the owner as the conn? */
        conn->socket = socket_ctx;

        ngtcp2_settings_default (&conn->conn_settings);

        conn->conn_settings.initial_ts = quiclib_ngtcp2_timestamp ();
        conn->conn_settings.log_printf = quiclib_ngtcp2_print;
        /*
         * Fine to just share the pointer - according to the ngtcp2_settings
         * docs, ngtcp2_conn_server_new makes a copy of the token
         */
        conn->conn_settings.token = hdr.token;

        conn->transport_params.stateless_reset_token_present = 0;
        memcpy (&conn->transport_params.original_dcid, &hdr.dcid,
            sizeof (ngtcp2_cid));
        conn->transport_params.original_dcid_present = 1;

        if (RAND_bytes (conn->transport_params.stateless_reset_token, 16) != 1) {
          GST_WARNING_OBJECT (socket_ctx->owner,
              "OpenSSL RAND_bytes failed to generate a stateless reset token:"
              " %s", ERR_error_string (ERR_get_error (), NULL));
        }

        switch (g_socket_address_get_family (peer_addr)) {
        case G_SOCKET_FAMILY_IPV4:
        {
          struct sockaddr_in local_sa, remote_sa;
          g_socket_address_to_native (local_addr, &local_sa,
              sizeof (struct sockaddr_in), NULL);
          g_socket_address_to_native (peer_addr, &remote_sa,
              sizeof (struct sockaddr_in), NULL);
          ngtcp2_path_storage_init (&conn->path,
              (ngtcp2_sockaddr *) &local_sa, sizeof (struct sockaddr_in),
              (ngtcp2_sockaddr *) &remote_sa, sizeof (struct sockaddr_in),
              (void *) conn);
          break;
        }
        case G_SOCKET_FAMILY_IPV6:
        {
          struct sockaddr_in6 local_sa, remote_sa;
          g_socket_address_to_native (local_addr, &local_sa,
              sizeof (struct sockaddr_in6), NULL);
          g_socket_address_to_native (peer_addr, &remote_sa,
              sizeof (struct sockaddr_in6), NULL);
          ngtcp2_path_storage_init (&conn->path,
              (ngtcp2_sockaddr *) &local_sa, sizeof (struct sockaddr_in6),
              (ngtcp2_sockaddr *) &remote_sa, sizeof (struct sockaddr_in6),
              (void *) conn);
          break;
        }
        default:
          GST_ERROR_OBJECT (socket_ctx->owner,
              "Received unknown socket family %d",
              g_socket_address_get_family (peer_addr));
          return FALSE;
        }

        quiclib_print_ngtcp2_transport_params (
            GST_QUICLIB_TRANSPORT_CONTEXT (conn), conn->transport_params);

        rv = ngtcp2_conn_server_new (&conn->quic_conn, dcid, new_scid,
            &conn->path.path, hdr.version, &quiclib_ngtcp2_server_callbacks,
            &conn->conn_settings, &conn->transport_params, NULL,
            (void *) conn);
        if (rv != 0) {
          GST_ERROR_OBJECT (socket_ctx->owner,
              "Failed to create new server instance: %s",
              ngtcp2_strerror (rv));
          g_free (conn);
          continue;
        }

        conn->ssl = SSL_new (server->ssl_ctx);
        if (conn->ssl == NULL) {
          GST_ERROR_OBJECT (socket_ctx->owner,
              "Failed to configure server SSL context");
          ngtcp2_conn_del (conn->quic_conn);
          g_free (conn);
          continue;
        }

#ifdef OPENSSL_DEBUG
        SSL_set_msg_callback (conn->ssl, quiclib_openssl_dbg_cb);
        SSL_set_msg_callback_arg (conn->ssl, (void *) conn);
#endif

        quiclib_enable_tls_export (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
            conn->ssl);

        conn->conn_ref.get_conn = quiclib_get_ngtcp2_conn;
        conn->conn_ref.user_data = (void *) conn;

        SSL_set_app_data (conn->ssl, &conn->conn_ref);
        SSL_set_accept_state (conn->ssl);
        SSL_set_quic_early_data_enabled (conn->ssl, 1);

        ngtcp2_conn_set_tls_native_handle (conn->quic_conn, conn->ssl);

        debug_remote_addr = g_socket_connectable_to_string (
            G_SOCKET_CONNECTABLE (peer_addr));
        GST_DEBUG_OBJECT (socket_ctx->owner,
            "New client connect from %s, SCID %s DCID %s",
            debug_remote_addr, quiclib_cidtostr (new_scid, debug_scid_str),
            quiclib_cidtostr (dcid, debug_dcid_str));

        conn->cids = g_list_append (conn->cids, new_scid);
        conn->cids = g_list_append (conn->cids, dcid);
      }
    } else {
      conn = GST_QUICLIB_TRANSPORT_CONNECTION (socket_ctx->owner);
    }

    if (ngtcp2_conn_in_closing_period (conn->quic_conn)) {
      gchar *debug_remote_addr = g_socket_connectable_to_string (
          G_SOCKET_CONNECTABLE (peer_addr));
      GST_WARNING_OBJECT (socket_ctx->owner,
          "Connection with %s is in closing period", debug_remote_addr);
      g_free (debug_remote_addr);
      continue;
    }

    if (ngtcp2_conn_in_draining_period (conn->quic_conn)) {
      gchar *debug_remote_addr = g_socket_connectable_to_string (
          G_SOCKET_CONNECTABLE (peer_addr));
      GST_WARNING_OBJECT (socket_ctx->owner,
          "Connection with %s is in draining period", debug_remote_addr);
      g_free (debug_remote_addr);
      continue;
    }

    rv = quiclib_transport_process_packet (conn, &pi, buf, bytes_read);
    if (rv != 0) {
      continue;
    }

    rv = quiclib_ngtcp2_conn_write (conn, -1, NULL, 0, 0, NULL);
    if (rv != 0) {
      continue;
    }

    /*
     * Wake up any threads waiting for cwnd
     */
    g_cond_signal (&conn->cond);
  } while (bytes_read > 0);

  if (err != NULL) {
    g_error_free (err);
  }

  return bytes_read == 0?TRUE:FALSE;
}

QuicLibSocketContext *
quiclib_open_socket (GstQuicLibTransportContext *ctx, GSocketAddress *addr)
{
  GstQuicLibTransportContextPrivate *priv;
  GSocketAddress *local, *remote;
  gchar *debug_addr;
  GSocket *socket;
  GSource *source;
  QuicLibSocketContext *socket_ctx;
  GSocketFamily fam;
  GError *err;

  priv = gst_quiclib_transport_context_get_instance_private (ctx);
  debug_addr =
      g_socket_connectable_to_string (G_SOCKET_CONNECTABLE (addr));

  fam = g_socket_address_get_family ((GSocketAddress *) addr);

  socket = g_socket_new (fam, G_SOCKET_TYPE_DATAGRAM, G_SOCKET_PROTOCOL_UDP,
      &err);

  if (socket == NULL) {
    GST_ERROR_OBJECT (ctx, "Failed to open socket: %s", err->message);
    goto no_socket;
  }

  switch (fam) {
  case G_SOCKET_FAMILY_IPV4:
    if (!g_socket_set_option (socket, IPPROTO_IP, IP_PKTINFO, 1, &err)) {
      GST_ERROR_OBJECT (ctx, "Couldn't set IP_PKTINFO: %s", err->message);
      goto no_bind;
    }

    if (!g_socket_set_option (socket, IPPROTO_IP, IP_RECVTOS, 1, &err)) {
      GST_WARNING_OBJECT (ctx, "Couldn't enable ECN for IPv4: %s",
          err->message);
    }

    if (!g_socket_set_option (socket, IPPROTO_IP, IP_MTU_DISCOVER, 1, &err)) {
      GST_WARNING_OBJECT (ctx, "Couldn't enable MTU discovery for IPv4: %s",
          err->message);
    }

#if defined(IP_DONTFRAG)
    if (!g_socket_set_option (socket, IPPROTO_IP, IP_DONTFRAG, 1, &err)) {
      GST_WARNING_OBJECT (ctx,
          "Couldn't enable the don't fragment socket option for IPv4: %s",
          err->message);
    }
#endif
    break;
  case G_SOCKET_FAMILY_IPV6:
    if (!g_socket_set_option (socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1, &err))
    {
      GST_ERROR_OBJECT (ctx, "Couldn't set IPV6_RECVPKTINFO: %s", err->message);
      goto no_bind;
    }

    if (!g_socket_set_option (socket, IPPROTO_IPV6, IPV6_RECVTCLASS, 1, &err)) {
      GST_WARNING_OBJECT (ctx, "Couldn't enable ECN for IPv6: %s",
          err->message);
    }

    if (!g_socket_set_option (socket, IPPROTO_IPV6, IPV6_MTU_DISCOVER, 1,
        &err)) {
      GST_WARNING_OBJECT (ctx, "Couldn't enable MTU discovery for IPv6: %s",
          err->message);
    }

#if defined(IPV6_DONTFRAG)
    if (!g_socket_set_option (socket, IPPROTO_IPV6, IPV6_DONTFRAG, 1, &err)) {
      GST_WARNING_OBJECT (ctx,
          "Couldn't enable the don't fragment socket option for IPv6: %s",
          err->message);
    }
#endif
    break;
  default:
    g_assert (fam == G_SOCKET_FAMILY_IPV4 || fam == G_SOCKET_FAMILY_IPV6);
  }

  g_socket_set_blocking (socket, FALSE);

  if (QUICLIB_SERVER (ctx)) {
    local = addr;
    if (g_socket_bind (socket, local, TRUE, &err) == FALSE) {
      GST_ERROR_OBJECT (ctx,
          "Couldn't bind local listening socket to address %s: %s", debug_addr,
          err->message);
      goto no_bind;
    }
  } else {
    remote = addr;
    if (g_socket_connect (socket, remote, NULL, &err) == FALSE) {
      GST_ERROR_OBJECT (ctx, "Couldn't connect to remote address %s: %s",
          debug_addr, err->message);
      goto no_bind;
    }

    local = g_socket_get_local_address (socket, &err);
    if (local == NULL) {
      GST_ERROR_OBJECT (ctx, "Couldn't get local address: %s", err->message);
      goto no_bind;
    }
  }

  source = g_socket_create_source (socket, G_IO_IN, NULL);

  socket_ctx = g_malloc (sizeof (QuicLibSocketContext));
  if (socket_ctx == NULL) {
    GST_ERROR_OBJECT (ctx, "Couldn't allocate memory for the socket context");
    goto no_source_ctx;
  }

  socket_ctx->owner = ctx;
  socket_ctx->socket = socket;
  socket_ctx->source = source;

  priv->loop_context = g_main_context_new ();
  priv->loop = g_main_loop_new (priv->loop_context, FALSE);
  priv->loop_thread = g_thread_new ("quiclib-transport",
      quiclib_transport_context_loop_thread, priv);

  /*
   * So this takes a GSourceFunc argument, which carries a single argument, but
   * socket_source_dispatch actually calls a function pointer with three args?
   *
   * What the hell guys?
   */
  g_source_set_callback (source, (GSourceFunc) quiclib_data_received,
      socket_ctx, NULL);

  g_source_attach (source,
      gst_quiclib_transport_context_get_loop_context (ctx));

  GST_DEBUG_OBJECT (ctx,
      "Opened %s socket %p with %s address %s, source %p, ctx %p",
      QUICLIB_SERVER (ctx)?"server":"client", socket_ctx->socket,
          QUICLIB_SERVER (ctx)?"local":"peer", debug_addr,
              socket_ctx->source, socket_ctx);

  g_free (debug_addr);
  if (local != addr) {
    g_object_unref (local);
  }

  return socket_ctx;

  no_source_ctx:
  if (local != addr) {
    g_object_unref (local);
  }
  g_source_unref (source);
  no_bind:
  g_socket_close (socket, NULL);
  no_socket:
  g_error_free (err);
  g_free (debug_addr);
  return NULL;
}

void
quiclib_open_server_socket_foreach (gpointer data, gpointer user_data)
{
  GstQuicLibServerContext *ctx = GST_QUICLIB_SERVER_CONTEXT (user_data);
  QuicLibSocketContext *socket = quiclib_open_socket (
      GST_QUICLIB_TRANSPORT_CONTEXT (ctx), (GSocketAddress *) data);

  ctx->sockets = g_slist_prepend (ctx->sockets, socket);
}


GstQuicLibServerContext *
gst_quiclib_transport_server_listen (GstQuicLibTransportUser *user,
    GSList *listen_addrs, const gchar *pkey_location,
    const gchar *cert_location, const gchar *sni, GSList *accept_alpns,
    gpointer app_ctx)
{
  int rv;
  GstQuicLibServerContext *server =
      g_object_new (GST_TYPE_QUICLIB_SERVER_CONTEXT, "user", user, "app_ctx",
          app_ctx, PROP_PRIVKEY_LOCATION_SHORTNAME, pkey_location,
          PROP_CERT_LOCATION_SHORTNAME, cert_location,
          PROP_SNI_SHORTNAME, sni, NULL);
  if (server == NULL) return NULL;

  server->ssl_ctx = SSL_CTX_new (TLS_server_method ());
  if (server->ssl_ctx == NULL) {
    GST_ERROR_OBJECT (QUICLIB_PARENT (server),
        "Failed to allocate new server SSL context: %s",
        ERR_error_string (ERR_get_error (), NULL));
    goto error;
  }

#ifdef OPENSSL_DEBUG
  SSL_CTX_set_msg_callback (server->ssl_ctx, quiclib_openssl_dbg_cb);
  SSL_CTX_set_msg_callback_arg (server->ssl_ctx, (void *) server);
#endif

  rv = ngtcp2_crypto_quictls_configure_server_context (server->ssl_ctx);
  if (rv != 0) {
    GST_ERROR_OBJECT (QUICLIB_PARENT (server),
        "Failed to configure ngtcp2/openssl server ctx");
    goto error;
  }

  SSL_CTX_set_max_early_data (server->ssl_ctx, UINT32_MAX);
  SSL_CTX_set_options (server->ssl_ctx, SSL_OP_SINGLE_ECDH_USE |
      SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_ANTI_REPLAY);
  SSL_CTX_set_mode (server->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  SSL_CTX_set_alpn_select_cb (server->ssl_ctx,
      quiclib_ssl_select_proto_cb, (void *) server);
  SSL_CTX_set_default_verify_paths (server->ssl_ctx);

  if (SSL_CTX_use_certificate_chain_file (server->ssl_ctx,
      server->cert_file_location) != 1) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (server),
        "SSL_CTX_user_certificate_chain_file failed to load certificate file "
        "%s, %s", server->cert_file_location, ERR_error_string (
            ERR_get_error (), NULL));
    goto error;
  }

  if (strstr (server->priv_key_location, ".pkcs8")) {
    EVP_PKEY *pkey = NULL;
    FILE *fp = fopen (server->priv_key_location, "r");
    if (!fp) {
      GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (server),
          "Opening private key from %s failed: %s", server->priv_key_location,
          strerror (errno));
      goto error;
    }
    pkey = d2i_PrivateKey_fp (fp, NULL);
    fclose (fp);
    if (!pkey) {
      GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (server),
          "Reading private key from %s failed", server->priv_key_location);
      goto error;
    }
    if (!SSL_CTX_use_PrivateKey (server->ssl_ctx, pkey)) {
      GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (server),
          "SSL_CTX_use_PrivateKey failed: %s",
          ERR_error_string (ERR_get_error (), NULL));
      goto error;
    }
  } else if (SSL_CTX_use_PrivateKey_file (server->ssl_ctx,
      server->priv_key_location, SSL_FILETYPE_PEM) != 1) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (server),
        "SSL_CTX_use_PrivateKey_file for %s failed: %s",
        server->priv_key_location, ERR_error_string (ERR_get_error (), NULL));
    goto error;
  }

  server->acceptable_alpns = g_slist_copy_deep (accept_alpns,
      quiclib_copy_gcharstring, NULL);

  server->cert_file_location = cert_location;
  server->priv_key_location = pkey_location;
  server->sni_host = sni;

  g_slist_foreach (listen_addrs, quiclib_open_server_socket_foreach, server);

  gst_quiclib_transport_context_set_state (
      GST_QUICLIB_TRANSPORT_CONTEXT (server), QUIC_STATE_LISTENING);

  return server;

  error:
  if (server->ssl_ctx) {
    SSL_CTX_free (server->ssl_ctx);
  }
  g_object_unref (server);
  server = NULL;
  return NULL;
}

GstQuicLibTransportConnection *
gst_quiclib_transport_client_connect (GstQuicLibTransportUser *user,
    GInetSocketAddress *location, const gchar *hostname, const gchar *alpn,
    gpointer app_ctx)
{
  gint rv;
  ngtcp2_cid *dcid = NULL, *scid = NULL;
  gchar dcid_str[CID_STR_LEN], scid_str[CID_STR_LEN];
  GError *err = NULL;
  struct sockaddr *localsa, *remotesa;
  gsize localsa_size, remotesa_size;
  gchar *debug_local_addr, *debug_remote_addr;
  GstQuicLibTransportConnection *conn =
      g_object_new (GST_TYPE_QUICLIB_TRANSPORT_CONNECTION, NULL);
  if (conn == NULL) return NULL;

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "New connection context: %p", conn);

  gst_quiclib_transport_context_set_user (
      GST_QUICLIB_TRANSPORT_CONTEXT (conn), user);
  gst_quiclib_transport_context_set_app_ctx (
      GST_QUICLIB_TRANSPORT_CONTEXT (conn), app_ctx);

  conn->ssl_ctx = SSL_CTX_new (TLS_client_method ());
  if (conn->ssl_ctx == NULL) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Failed to allocate new client SSL context: %s",
        ERR_error_string (ERR_get_error (), NULL));
    goto free_conn;
  }

#ifdef OPENSSL_DEBUG
  SSL_CTX_set_msg_callback (conn->ssl_ctx, quiclib_openssl_dbg_cb);
  SSL_CTX_set_msg_callback_arg (conn->ssl_ctx, conn);
#endif

  rv = ngtcp2_crypto_quictls_configure_client_context (conn->ssl_ctx);
  if (rv != 0) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Failed to configure the client SSL context");
    goto free_ssl_ctx;
  }

  g_object_set (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      PROP_LOCATION_SHORT, location, NULL);

  conn->socket = quiclib_open_socket (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      G_SOCKET_ADDRESS (location));

  debug_remote_addr =
      g_socket_connectable_to_string (G_SOCKET_CONNECTABLE (location));

  debug_local_addr =
      g_socket_connectable_to_string (G_SOCKET_CONNECTABLE (
          g_socket_get_local_address (conn->socket->socket, &err)));

  localsa_size = g_socket_address_get_native_size (
      g_socket_get_local_address (conn->socket->socket, &err));
  remotesa_size =
      g_socket_address_get_native_size (G_SOCKET_ADDRESS (location));
  localsa = (struct sockaddr *) g_malloc (localsa_size);
  remotesa = (struct sockaddr *) g_malloc (remotesa_size);
  if (g_socket_address_to_native (
      g_socket_get_local_address (conn->socket->socket, NULL), localsa,
      localsa_size, &err) == FALSE) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Failed to convert local socket address %s to native sockaddr: %s",
        debug_local_addr, err->message);
    goto free_sa;
  }

  if (g_socket_address_to_native (G_SOCKET_ADDRESS (location), remotesa,
      remotesa_size, &err) == FALSE) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Failed to convert remote socket address %s to native sockaddr: %s",
        g_socket_connectable_to_string (G_SOCKET_CONNECTABLE (location)),
        err->message);
    goto remove_listener;
  }

  ngtcp2_path_storage_init (&conn->path, localsa, localsa_size, remotesa,
      remotesa_size, (void *) conn);

  dcid = g_malloc (sizeof (ngtcp2_cid));
  scid = g_malloc (sizeof (ngtcp2_cid));
  if (dcid == NULL || scid == NULL) {
    goto remove_listener;
  }

  if (quiclib_ngtcp2_get_new_connection_id (NULL, dcid, NULL,
      NGTCP2_MIN_INITIAL_DCIDLEN, (void *) conn) < 0) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Failed to generate initial DCID");
    goto remove_listener;
  }

  if (quiclib_ngtcp2_get_new_connection_id (NULL, scid, NULL, 8,
      (void *) conn) < 0) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Failed to generate initial SCID");
    goto remove_listener;
  }

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Opening connection with QUIC peer %s with local address %s",
      debug_remote_addr, debug_local_addr);

  ngtcp2_settings_default (&conn->conn_settings);

  conn->conn_settings.initial_ts = quiclib_ngtcp2_timestamp ();
  conn->conn_settings.log_printf = quiclib_ngtcp2_print;

  quiclib_cidtostr (dcid, dcid_str);
  quiclib_cidtostr (scid, scid_str);

  /*
   * Retrieve the transport params from the base class
   */
  g_object_get (GST_QUICLIB_TRANSPORT_CONTEXT (conn),

      PROP_MAX_STREAM_DATA_BIDI_REMOTE_SHORTNAME,
        &conn->transport_params.initial_max_stream_data_bidi_local,
      PROP_MAX_STREAM_DATA_UNI_REMOTE_SHORTNAME,
        &conn->transport_params.initial_max_stream_data_uni,
      PROP_MAX_DATA_REMOTE_SHORTNAME,
        &conn->transport_params.initial_max_data,
      PROP_MAX_STREAMS_BIDI_REMOTE_SHORTNAME,
        &conn->transport_params.initial_max_streams_bidi,
      PROP_MAX_STREAMS_UNI_REMOTE_SHORTNAME,
        &conn->transport_params.initial_max_streams_uni,
      NULL);

  conn->transport_params.initial_max_stream_data_bidi_remote =
      conn->transport_params.initial_max_stream_data_bidi_local;

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Opening connection with QUIC peer %s with local address %s, DCID %s"
      "and SCID %s", debug_remote_addr, debug_local_addr, dcid_str, scid_str);

  quiclib_print_ngtcp2_transport_params (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        conn->transport_params);

  rv = ngtcp2_conn_client_new (&conn->quic_conn, dcid, scid,
      &conn->path.path, NGTCP2_PROTO_VER_V1, &quiclib_ngtcp2_client_callbacks,
      &conn->conn_settings, &conn->transport_params, NULL, (void *) conn);
  if (rv != 0) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "ngtcp2 failed to create new client: %s", ngtcp2_strerror (rv));
    goto remove_listener;
  }

  conn->ssl = SSL_new (conn->ssl_ctx);
  if (conn->ssl == NULL) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Couldn't create SSL object for connection: %s",
        ERR_error_string (ERR_get_error (), NULL));
    goto remove_listener;
  }

#ifdef OPENSSL_DEBUG
  SSL_set_msg_callback (conn->ssl, quiclib_openssl_dbg_cb);
  SSL_set_msg_callback_arg (conn->ssl, (void *) conn);
#endif

  conn->conn_ref.get_conn = quiclib_get_ngtcp2_conn;
  conn->conn_ref.user_data = (void *) conn;

  SSL_set_app_data (conn->ssl, &conn->conn_ref);
  SSL_set_connect_state (conn->ssl);
  if (alpn) {
    guchar alpn_len = (guchar) strlen (alpn);
    guchar alpn_plf[alpn_len + 1];
    alpn_plf[0] = alpn_len;
    memcpy (alpn_plf + 1, alpn, alpn_len);
    if (SSL_set_alpn_protos (conn->ssl, alpn_plf, alpn_len + 1) != 0) {
      GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "Failed to set client ALPN");
    }

    conn->alpn = g_strndup (alpn, alpn_len);
  }

  SSL_set_tlsext_host_name (conn->ssl, hostname);

  SSL_set_quic_transport_version (conn->ssl,
      TLSEXT_TYPE_quic_transport_parameters);

  ngtcp2_conn_set_tls_native_handle (conn->quic_conn, conn->ssl);

  quiclib_enable_tls_export (GST_QUICLIB_TRANSPORT_CONTEXT (conn), conn->ssl);

  rv = quiclib_ngtcp2_conn_write (conn, -1, NULL, 0, 0, NULL);
  if (rv != 0) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn), "conn_write failed");
    ngtcp2_conn_del (conn->quic_conn);
    SSL_free (conn->ssl);
    goto remove_listener;
  }

  GST_INFO_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Initiated %s connection with remote peer %s", alpn,
      debug_remote_addr);

  gst_quiclib_transport_context_set_state (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      QUIC_STATE_INITIAL);

  g_free (debug_remote_addr);
  g_free (debug_local_addr);

  return conn;

  remove_listener:
  if (dcid != NULL) {
    g_free (dcid);
  }
  if (scid != NULL) {
    g_free (scid);
  }
  g_source_destroy (conn->socket->source);
  free_sa:
  g_free (localsa);
  g_free (remotesa);
  g_free (debug_remote_addr);
  g_free (debug_local_addr);
  g_object_unref (conn->socket->socket);
  g_free (conn->socket);
  free_ssl_ctx:
  SSL_CTX_free (conn->ssl_ctx);
  free_conn:
  g_object_unref (conn);
  if (err != NULL) {
    g_error_free (err);
  }
  return NULL;
}

GstQUICMode
gst_quiclib_transport_get_mode (GstQuicLibTransportContext *ctx)
{
  if (QUICLIB_SERVER (ctx)) return QUICLIB_MODE_SERVER;
  if (QUICLIB_CLIENT (ctx)) return QUICLIB_MODE_CLIENT;
  return -1;
}

GstQuicLibTransportState
gst_quiclib_transport_get_state (GstQuicLibTransportContext *ctx)
{
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);
  return priv->state;
}

gpointer
gst_quiclib_transport_get_app_ctx (GstQuicLibTransportContext *ctx)
{
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);
  return priv->app_ctx;
}

void
gst_quiclib_transport_set_app_ctx (GstQuicLibTransportContext *ctx,
    gpointer app_ctx)
{
  GstQuicLibTransportContextPrivate *priv =
      gst_quiclib_transport_context_get_instance_private (ctx);
  priv->app_ctx = app_ctx;
}

GSList *
gst_quiclib_transport_get_listening_addrs (GstQuicLibServerContext *server)
{
  GSList *addrs;
  GSList *sockets = server->sockets;

  while (sockets != NULL) {
    GSocketAddress *sa = g_socket_get_local_address (
        ((QuicLibSocketContext *) sockets->data)->socket, NULL);
    addrs = g_slist_prepend (addrs, sa);
    sockets = sockets->next;
  }

  return addrs;
}

GSList *
gst_quiclib_transport_get_acceptable_alpns (GstQuicLibServerContext *server)
{
  return server->acceptable_alpns;
}

GInetSocketAddress *
gst_quiclib_transport_get_local (GstQuicLibTransportConnection *conn)
{
  return (GInetSocketAddress *) g_socket_address_new_from_native (
      conn->path.path.local.addr, conn->path.path.local.addrlen);
}

GInetSocketAddress *
gst_quiclib_transport_get_peer (GstQuicLibTransportConnection *conn)
{
  return (GInetSocketAddress *) g_socket_address_new_from_native (
      conn->path.path.remote.addr, conn->path.path.remote.addrlen);
}

gboolean
quiclib_close_wait (gpointer user_data)
{
  gboolean rv = G_SOURCE_CONTINUE;
  GstQuicLibTransportConnection *conn =
      (GstQuicLibTransportConnection *) user_data;

  gst_quiclib_transport_context_lock (conn);

  if (ngtcp2_conn_in_closing_period (conn->quic_conn) ||
      ngtcp2_conn_in_draining_period (conn->quic_conn))
  {
    g_object_unref (gst_quiclib_transport_context_get_timeout (conn));
    gst_quiclib_transport_context_set_timeout (conn, NULL);
    rv = G_SOURCE_REMOVE;
  } else {
    gst_quiclib_transport_context_set_state (
        GST_QUICLIB_TRANSPORT_CONTEXT (conn), QUIC_STATE_CLOSED);
  }

  gst_quiclib_transport_context_unlock (conn);

  return rv;
}

gint
quiclib_transport_process_packet (GstQuicLibTransportConnection *conn,
    const ngtcp2_pkt_info *pktinfo, uint8_t *pkt, size_t pktlen)
{
  gint rv;
  ngtcp2_tstamp expiry, now;

  gst_quiclib_transport_context_lock (conn);

  rv = ngtcp2_conn_read_pkt (conn->quic_conn, &conn->path.path, pktinfo, pkt,
      pktlen, quiclib_ngtcp2_timestamp());

  gst_quiclib_transport_context_unlock (conn);

  if (rv != 0) {
    GST_INFO_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "ngtcp2 failed to read packet: %s", ngtcp2_strerror (rv));
    switch (rv) {
    case NGTCP2_ERR_DRAINING:
    {
      GstQuicLibTransportUserInterface *iface =
            QUICLIB_TRANSPORT_USER_GET_IFACE (
                gst_quiclib_transport_context_get_user (conn));

      GST_INFO_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "Draining period is starting");
      quiclib_set_timer (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          quiclib_close_wait,
          ngtcp2_conn_get_pto (conn->quic_conn) / NGTCP2_MILLISECONDS * 3);

      iface->connection_closed (gst_quiclib_transport_context_get_user (conn),
          GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          gst_quiclib_transport_get_peer (conn));

      return -2;
    }
    case NGTCP2_ERR_RETRY:
      GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "TODO: implement address validation and retry");
      g_assert (0);
      break;
    case NGTCP2_ERR_DROP_CONN:
      /* Just drop the connection silently */
      return -1;
    case NGTCP2_ERR_CRYPTO:
      GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
          "Error in TLS stack: %s", SSL_alert_type_string (
              ngtcp2_conn_get_tls_alert (conn->quic_conn)));
      gst_quiclib_transport_disconnect (conn, FALSE,
          QUICLIB_CLOSE_CRYPTO_ERROR);
      return -1;
    }
  }

  expiry = ngtcp2_conn_get_expiry (conn->quic_conn);
  now = quiclib_ngtcp2_timestamp ();

  GST_TRACE_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "ngtcp2 expiry time %lu, time now %lu", expiry, now);

  if (expiry <= now) {
    quiclib_cancel_timer (GST_QUICLIB_TRANSPORT_CONTEXT (conn));
    quiclib_timer_expired ((void *) conn);
  } else {
    quiclib_set_timer (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        quiclib_timer_expired, (expiry - now) / NGTCP2_MILLISECONDS);
  }

  return 0;
}

gint
gst_quiclib_transport_disconnect (GstQuicLibTransportConnection *conn,
    gboolean app_error, guint reason)
{
  /*ngtcp2_path path;*/
  ngtcp2_ssize written;
  ngtcp2_pkt_info pi;
  uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];

  if (app_error) {
    ngtcp2_ccerr_set_application_error (&conn->last_error, reason, NULL, 0);
  } else {
    ngtcp2_ccerr_set_transport_error (&conn->last_error, reason, NULL, 0);
  }

  gst_quiclib_transport_context_set_state (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      QUIC_STATE_HALF_CLOSED);

  gst_quiclib_transport_context_lock (conn);
  written = ngtcp2_conn_write_connection_close (conn->quic_conn,
      &conn->path.path, &pi, buf, NGTCP2_MAX_UDP_PAYLOAD_SIZE,
      &conn->last_error, quiclib_ngtcp2_timestamp ());

  if (written <= 0) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Couldn't write connection close packet: %s",
        ngtcp2_strerror ((int) written));
    return -1;
  }

  written = ngtcp2_conn_write_pkt (conn->quic_conn, &conn->path.path, &pi,
      buf, (size_t) written, quiclib_ngtcp2_timestamp ());

  if (!ngtcp2_conn_in_closing_period (conn->quic_conn) &&
      !ngtcp2_conn_in_draining_period (conn->quic_conn))
  {
    quiclib_set_timer (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        quiclib_close_wait,
        ngtcp2_conn_get_pto (conn->quic_conn) / NGTCP2_MILLISECONDS * 3);
  } else {
    gst_quiclib_transport_context_set_state (
        GST_QUICLIB_TRANSPORT_CONTEXT (conn), QUIC_STATE_CLOSED);
  }

  gst_quiclib_transport_context_unlock (conn);

  return 0;
}

gboolean
gst_quiclib_transport_server_remove_listens (GstQuicLibServerContext *ctx,
    GSList *addrs)
{
  g_assert (0);

  /* TODO */

  return FALSE;
}

void
gst_quiclib_transport_set_hdrctx (GstQuicLibTransportConnection *conn,
    void *ctx)
{

}

void *
gst_quiclib_transport_get_hdrctx (GstQuicLibTransportConnection *ctx)
{
  return NULL;
}

struct _GstQuicLibUnmap {
  GstMapInfo map;
  gsize end_offset;
  GstMemory *mem;
};

size_t
quiclib_buffer_to_vec (GstBuffer *buf, ngtcp2_vec **vec, GList **unmap)
{
  size_t i, n = gst_buffer_n_memory (buf);
  ngtcp2_vec *v = g_new0 (ngtcp2_vec, n);
  GList *maps = NULL;
  gsize offset = 0;
  if (v == NULL) return 0;

  for (i = 0; i < n; i++) {
    struct _GstQuicLibUnmap *map = g_new0 (struct _GstQuicLibUnmap, 1);
    map->mem = gst_buffer_peek_memory (buf, i);
    gst_memory_map (map->mem, &map->map, GST_MAP_READ);
    /* Unmapped in quiclib_buffer_unmap */
    v[i].base = map->map.data;
    v[i].len = map->map.size;
    offset += map->map.size;
    map->end_offset = offset;
    maps = g_list_append (maps, map);
  }

  *vec = v;
  *unmap = maps;
  return n;
}

void
quiclib_buffer_unmap (GList **map)
{
  GList *maps = *map;
  while (maps != NULL) {
    struct _GstQuicLibUnmap *unmap =
        (struct _GstQuicLibUnmap *) maps->data;
    gst_memory_unmap (unmap->mem, &unmap->map);
    g_free (unmap);
    maps = g_list_delete_link (maps, maps);
  }
  *map = maps;
}

gint64
gst_quiclib_transport_open_stream (GstQuicLibTransportConnection *conn,
    gboolean bidirectional, gpointer stream_ctx)
{
  gint rv;
  gint64 stream_id = -1;

  gst_quiclib_transport_context_lock (conn);

  if (ngtcp2_conn_get_handshake_completed (conn->quic_conn) == 0) {
    GST_WARNING_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Cannot open stream as handshake has not completed yet");
    gst_quiclib_transport_context_unlock (conn);
    return GST_QUICLIB_ERR;
  }

  if (bidirectional) {
    rv = ngtcp2_conn_open_bidi_stream (conn->quic_conn, &stream_id,
        stream_ctx);
  } else {
    rv = ngtcp2_conn_open_uni_stream (conn->quic_conn, &stream_id, stream_ctx);
  }

  gst_quiclib_transport_context_unlock (conn);

  if (rv != 0) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Failed to open new QUIC stream: %s", ngtcp2_strerror (rv));
    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
      return GST_QUICLIB_ERR_STREAM_ID_BLOCKED;
    }
    return GST_QUICLIB_ERR;
  }

  if (quiclib_alloc_stream_context (conn, stream_id) == FALSE) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Failed to allocate stream context");
    gst_quiclib_transport_context_lock (conn);
    ngtcp2_conn_shutdown_stream (conn->quic_conn, 0, stream_id, 0);
    gst_quiclib_transport_context_unlock (conn);
    return GST_QUICLIB_ERR;
  }

  rv = quiclib_ngtcp2_conn_write (conn, -1, NULL, 0, 0, NULL);
  if (rv != 0) {
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn), "conn_write failed");
  }

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Opened new %sdirectional QUIC stream %ld",
      (bidirectional)?("bi"):("uni"), stream_id);

  return stream_id;
}

GstQuicLibStreamState
gst_quiclib_transport_stream_state (GstQuicLibTransportConnection *conn,
    guint64 stream_id)
{
  GstQuicLibStreamState rv = QUIC_STREAM_OPEN;

  gst_quiclib_transport_context_lock (conn);

  if (ngtcp2_conn_get_max_stream_data_left (conn->quic_conn, (gint64) stream_id) == 0) {
    rv |= QUIC_STREAM_DATA_BLOCKED;
  }
  if (ngtcp2_conn_get_cwnd_left (conn->quic_conn) == 0) {
    rv |= QUIC_STREAM_CONNECTION_BLOCKED;
  }

  gst_quiclib_transport_context_unlock (conn);

  if (stream_id & 0x2) {
    if (conn->server) {
      if (stream_id & 0x1) {
        rv |= QUIC_STREAM_CLOSED_READING;
      } else {
        rv |= QUIC_STREAM_CLOSED_SENDING;
      }
    } else {
      if (stream_id & 0x1) {
        rv |= QUIC_STREAM_CLOSED_SENDING;
      } else {
        rv |= QUIC_STREAM_CLOSED_READING;
      }
    }
  }

  return rv;
}

typedef struct _GstQuicLibStreamClose GstQuicLibStreamClose;

struct _GstQuicLibStreamClose {
  GstMiniObject mini_object;

  guint64 stream_id;
  guint64 error_close;
};

GST_DEFINE_MINI_OBJECT_TYPE (GstQuicLibStreamClose, gst_quiclib_stream_close);

#define QUICLIB_TYPE_STREAM_CLOSE gst_quiclib_stream_close_get_type ()
#define QUICLIB_IS_STREAM_CLOSE(obj) \
    (GST_IS_MINI_OBJECT_TYPE (obj, QUICLIB_TYPE_STREAM_CLOSE))
#define QUICLIB_STREAM_CLOSE_CAST(obj) ((GstQuicLibStreamClose *) obj)

GstQuicLibStreamClose *
gst_quiclib_stream_close_new (guint64 stream_id, guint64 reason)
{
  GstQuicLibStreamClose *obj;

  obj = g_new (GstQuicLibStreamClose, 1);

  gst_mini_object_init (GST_MINI_OBJECT_CAST (obj), 0,
      QUICLIB_TYPE_STREAM_CLOSE, NULL, NULL, NULL);

  obj->stream_id = stream_id;
  obj->error_close = reason;

  return obj;
}

#define gst_quiclib_stream_close_ref(obj) \
    (GstQuicLibStreamClose *) gst_mini_object_ref (GST_MINI_OBJECT_CAST (obj));

#define gst_quiclib_stream_close_unref(obj) \
    gst_mini_object_unref (GST_MINI_OBJECT_CAST (obj));

static gboolean
_quiclib_transport_send_queue_source_prepare (GSource *source, gint *timeout)
{
  GstQuicLibTransportSendQueueSource *send_queue_src =
      (GstQuicLibTransportSendQueueSource *) source;

  GST_TRACE_OBJECT (send_queue_src->conn,
      "send_queue_source_prepare: cwnd %lu, queue length: %u, bytes: %lu",
      ngtcp2_conn_get_cwnd_left (send_queue_src->conn->quic_conn),
      g_async_queue_length (send_queue_src->queue), send_queue_src->queue_len);

  return (ngtcp2_conn_get_cwnd_left (send_queue_src->conn->quic_conn) &&
      g_async_queue_length (send_queue_src->queue) > 0);
}

static gboolean
_quiclib_transport_send_queue_source_dispatch (GSource *source, GSourceFunc cb,
    gpointer user_data)
{
  GstQuicLibTransportSendQueueSource *send_queue_src =
      (GstQuicLibTransportSendQueueSource *) source;
  GstMiniObject *obj;
  GQueue *replace = g_queue_new ();

  for (obj = GST_MINI_OBJECT (g_async_queue_pop (send_queue_src->queue));
      obj != NULL;
      obj = GST_MINI_OBJECT (g_async_queue_try_pop (send_queue_src->queue))) {

    if (GST_IS_BUFFER (obj)) {
      GstQuicLibStreamMeta *smeta;
      GstQuicLibDatagramMeta *dmeta;
      gssize bytes_sent = 0;
      GstQuicLibError err = GST_QUICLIB_ERR_OK;
      GstBuffer *buf = GST_BUFFER (obj);

      smeta = gst_buffer_get_quiclib_stream_meta (buf);
      if (smeta != NULL) {
        GST_TRACE_OBJECT (send_queue_src->conn, "Buffer of size %lu for stream "
            "ID %lu to send, stream data remaining %lu",
            gst_buffer_get_size (buf), smeta->stream_id,
            ngtcp2_conn_get_max_stream_data_left (
                send_queue_src->conn->quic_conn, smeta->stream_id));
        if (ngtcp2_conn_get_max_stream_data_left (send_queue_src->conn->quic_conn,
            smeta->stream_id) >= gst_buffer_get_size (buf)) {
          err = gst_quiclib_transport_send_stream (send_queue_src->conn,
              buf, smeta->stream_id, &bytes_sent);
        }
      }

      dmeta = gst_buffer_get_quiclib_datagram_meta (buf);
      if (dmeta != NULL) {
        GST_TRACE_OBJECT (send_queue_src->conn, "Buffer of size %lu for "
            "datagram to send", gst_buffer_get_size (buf));
        err = gst_quiclib_transport_send_datagram (send_queue_src->conn,
            buf, NULL, &bytes_sent);
      }

      if (err < 0) {
        /* An error! */
        GST_TRACE_OBJECT (send_queue_src->conn,
            "An error was encountered when sending buffer! %s",
            gst_quiclib_error_as_string(err));
        break;
      } else if (bytes_sent < gst_buffer_get_size (buf)) {
        GST_TRACE_OBJECT (send_queue_src->conn,
            "Managed to send %ld bytes of %ld", bytes_sent,
            gst_buffer_get_size (buf));
        if (bytes_sent > 0) {
          /*
           * Resize the buffer to account for what's been sent
           */
          gst_buffer_resize (buf, bytes_sent, -1);
        }

        g_queue_push_tail (replace, (gpointer) buf);
      }

      g_mutex_lock (&send_queue_src->mutex);
      send_queue_src->queue_len -= bytes_sent;
      g_mutex_unlock (&send_queue_src->mutex);
    } else if (QUICLIB_IS_STREAM_CLOSE (obj)) {
      GstQuicLibStreamClose *close_obj = QUICLIB_STREAM_CLOSE_CAST (obj);
      GList *it;
      gboolean needs_queuing = FALSE;

      GST_TRACE_OBJECT (send_queue_src->conn, "Queued stream close %lu",
          close_obj->stream_id);

      for (it = replace->head; it != NULL; it = it->next) {
        if (GST_IS_BUFFER (it->data)) {
          GstQuicLibStreamMeta *smeta =
              gst_buffer_get_quiclib_stream_meta (GST_BUFFER (it->data));
          if (smeta != NULL &&
              ((guint64) smeta->stream_id == close_obj->stream_id)) {
            needs_queuing = TRUE;
            break;
          }
        }
      }

      if (needs_queuing) {
        GST_TRACE_OBJECT (send_queue_src->conn,
            "Still data to send for stream %lu, requeueing",
            close_obj->stream_id);
        g_queue_push_tail (replace, (gpointer) obj);
      } else if (QUICLIB_STREAM_IS_UNI (close_obj->stream_id) ||
          close_obj->error_close) {
        GST_TRACE_OBJECT (send_queue_src->conn,
            "Forcing shutdown of stream %lu", close_obj->stream_id);
        gst_quiclib_transport_context_lock (send_queue_src->conn);
        if (ngtcp2_conn_shutdown_stream (send_queue_src->conn->quic_conn, 0,
            (gint64) close_obj->stream_id, close_obj->error_close) != 0) {
          GST_ERROR_OBJECT (obj, "Couldn't shut down stream %lu",
              close_obj->stream_id);
        }
        gst_quiclib_transport_context_unlock (send_queue_src->conn);
      } else if (quiclib_ngtcp2_conn_write (send_queue_src->conn,
            close_obj->stream_id, NULL, 0, 1, NULL) != 0) {
        GST_ERROR_OBJECT (obj, "Couldn't write end-of-stream for stream %lu",
            close_obj->stream_id);
      }
    }
  }

  if (g_queue_get_length (replace)) {
    GstMiniObject *obj;

    g_async_queue_lock (send_queue_src->queue);

    for (obj = GST_MINI_OBJECT (g_queue_pop_tail (replace)); obj != NULL;
        obj = GST_MINI_OBJECT (g_queue_pop_tail (replace))) {
      g_async_queue_push_front_unlocked (send_queue_src->queue, (gpointer) obj);
    }

    g_async_queue_unlock (send_queue_src->queue);
  }

  g_queue_free (replace);

  return TRUE;
}

static void
_quiclib_transport_send_queue_source_finalize (GSource *source)
{
  GstQuicLibTransportSendQueueSource *send_queue_src =
      (GstQuicLibTransportSendQueueSource *) source;

  g_async_queue_unref (send_queue_src->queue);
}

static GSourceFuncs _quiclib_transport_send_queue_source_funcs = {
    .prepare = _quiclib_transport_send_queue_source_prepare,
    .check = NULL,
    .dispatch = _quiclib_transport_send_queue_source_dispatch,
    .finalize = _quiclib_transport_send_queue_source_finalize
};

void
_ensure_quiclib_send_queue (GstQuicLibTransportConnection *conn)
{
  if (conn->send_queue_source == NULL) {
    GstQuicLibTransportContextPrivate *priv =
        gst_quiclib_transport_context_get_instance_private (
            GST_QUICLIB_TRANSPORT_CONTEXT (conn));

    conn->send_queue_source = (GstQuicLibTransportSendQueueSource *)
        g_source_new (&_quiclib_transport_send_queue_source_funcs,
          sizeof (GstQuicLibTransportSendQueueSource));

    conn->send_queue_source->conn = conn;
    conn->send_queue_source->queue_len = 0;

    g_mutex_init (&conn->send_queue_source->mutex);

    conn->send_queue_source->queue =
        g_async_queue_new_full ((GDestroyNotify) gst_buffer_unref);

    g_source_attach ((GSource *) conn->send_queue_source, priv->loop_context);
  }
}

gboolean
gst_quiclib_transport_close_stream (GstQuicLibTransportConnection *conn,
    guint64 stream_id, guint64 error_code)
{
  int rv = -1;

  if (error_code) {
    gst_quiclib_transport_context_lock (conn);
    rv = ngtcp2_conn_shutdown_stream (conn->quic_conn, 0, (gint64) stream_id,
        error_code);
    gst_quiclib_transport_context_unlock (conn);
  } else {
    rv = (int) quiclib_ngtcp2_conn_write (conn, stream_id, NULL, 0, 1, NULL);
  }

  return (rv == 0)?(TRUE):(FALSE);
}

GstQuicLibError
gst_quiclib_transport_send_buffer (GstQuicLibTransportConnection *conn,
    GstBuffer *buf)
{
  GstQuicLibStreamMeta *smeta;
  GstQuicLibDatagramMeta *dmeta;

  smeta = gst_buffer_get_quiclib_stream_meta (buf);
  if (smeta != NULL) {
    return gst_quiclib_transport_send_stream (conn, buf, smeta->stream_id);
  }

  dmeta = gst_buffer_get_quiclib_datagram_meta (buf);
  if (dmeta != NULL) {
    return gst_quiclib_transport_send_datagram (conn, buf, NULL);
  }

  return -1;
}

#if 0
void
quiclib_transport_print_buffer (GstQuicLibTransportContext *ctx, GstBuffer *buf)
{
  guint offset = 0;
  guint idx;

  GST_DEBUG_OBJECT (ctx, "GstBuffer %p has %u memory blocks",
      buf, gst_buffer_n_memory (buf));

  /*
   * Format:
   *
   * Buffer 0 (4):
   *    00000000 (00000000): e0 a1 b9 f3
   * Buffer 1 (12):
   *    00000000 (00000004): 01 45 aa f1 57 7f 21 00 00 9a be f1
   * Buffer 2 (1388):
   *    00000000 (00000016): a1 e7 ff 00 00 00 00 00 00 00 16 eb eb a0 f7 44
   *    00000016 (00000032): c4 d9 00 11 22 33 44 55 66 77 88 99 aa bb cc dd
   *    00000032 (00000048): (...)
   */

  for (idx = 0; idx < gst_buffer_n_memory (buf); idx++) {
    GstMemory *mem;
    GstMapInfo map;
    guint line_idx;

    mem = gst_buffer_peek_memory (buf, idx);
    gst_memory_map (mem, &map, GST_MAP_READ);

    GST_DEBUG_OBJECT (ctx, "Buffer %u (%lu)", idx, map.size);

    for (line_idx = 0; line_idx < (map.size / 16) + 1; line_idx++) {
      gchar bufline[80];
      gint bufline_offset = 0;
      guint data_idx = 0;

      bufline_offset = sprintf (bufline, "%08u (%08u):", line_idx * 16,
          offset + line_idx * 16);

      for (data_idx = line_idx * 16;
           data_idx < map.size && data_idx < (line_idx + 1) * 16; data_idx++) {
        guchar top_nibble = (map.data[data_idx] % 0xf0) >> 4;
        guchar bottom_nibble = map.data[data_idx] % 0x0f;
        bufline_offset += sprintf (bufline + bufline_offset, " %c%c",
            (top_nibble > 9)?(top_nibble + 87):(top_nibble + 48),
            (bottom_nibble > 9)?(bottom_nibble + 87):(bottom_nibble + 48));
      }

      GST_DEBUG_OBJECT (ctx, "\t%s", bufline);
    }

    offset += map.size;

    gst_memory_unmap (mem, &map);
  }
}
#endif

GstQuicLibError
gst_quiclib_transport_send_stream (GstQuicLibTransportConnection *conn,
    GstBuffer *buf, gint64 stream_id)
{
  ssize_t bytes_written = 0;
  ngtcp2_vec *vec = NULL, *vec_orig;
  GList *maps = NULL;
  size_t n;
  GstQuicLibStreamMeta *meta = gst_buffer_get_quiclib_stream_meta (buf);
  gsize buf_size = gst_buffer_get_size (buf);
  ssize_t last_rv = -1; /* DEBUG ONLY */

  if (stream_id < 0 && meta != NULL) {
    stream_id = meta->stream_id;
  }

  g_return_val_if_fail (stream_id >= 0, -1);

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Received %lu bytes for stream %lu", buf_size, stream_id);

  /*quiclib_transport_print_buffer (GST_QUICLIB_TRANSPORT_CONTEXT (conn), buf);*/

  if (!g_hash_table_lookup_extended (conn->streams, &stream_id, NULL,
      (gpointer *) &stream)){
    GST_ERROR_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Couldn't find stream context for stream %ld", stream_id);
    return GST_QUICLIB_ERR_STREAM_CLOSED;
  }

  n = quiclib_buffer_to_vec (buf, &vec, &maps);
  vec_orig = vec;

  g_return_val_if_fail (n != 0, -1);

  while (bytes_written < buf_size) {
    ssize_t rv = quiclib_ngtcp2_conn_write (conn, stream_id, vec, n, 0, buf);

    if (rv < 0) {
      break;
    }

    g_assert (rv > 0 || last_rv != 0);
    last_rv = rv;

    bytes_written += rv;
    GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
        "Written %ld bytes of data on stream %ld, %ld remaining of %ld - "
        "cwnd %lu, stream data %lu, max data %lu", rv, stream_id,
        buf_size - bytes_written, buf_size,
        ngtcp2_conn_get_cwnd_left (conn->quic_conn),
        ngtcp2_conn_get_max_stream_data_left (conn->quic_conn, stream_id),
        ngtcp2_conn_get_max_data_left (conn->quic_conn));

    if (rv == 0) {
      /*
       * Wait until there's flow window to send again
       */
      g_mutex_lock (&conn->mutex);

      while (ngtcp2_conn_get_cwnd_left (conn->quic_conn) == 0) {
        gint64 end_time;

        /*
         * TODO: Is it worth having the end time be configurable? 100ms is very
         * much a finger-in-the-air value to stop it busy waiting.
         */
        end_time = g_get_monotonic_time () + 100 * G_TIME_SPAN_MILLISECOND;
        g_cond_wait_until (&conn->cond, &conn->mutex, end_time);
      }

      g_mutex_unlock (&conn->mutex);
    }
    if (buf_size - bytes_written > 0) {
      /* Adjust the vectors as necessary */

      while (rv >= vec[0].len) {
        rv -= vec[0].len;
        vec += 1; /* Go to the next buffer in the vector */
        n -= 1;
      }

      if (rv > 0) {
        vec[0].base += rv;
        vec[0].len -= (size_t) rv;
      }
    }
  }

  GST_DEBUG_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (conn),
      "Written %ld total bytes from %ld", bytes_written, buf_size);

  quiclib_buffer_unmap (&maps);

  g_free (vec_orig);

  return bytes_written;
}

GstQuicLibError
gst_quiclib_transport_send_datagram (GstQuicLibTransportConnection *conn,
    GstBuffer *buf, GstQuicLibDatagramTicket *ticket)
{
  ssize_t bytes_written;
  ngtcp2_vec *vec = NULL;
  GList *maps = NULL;
  size_t n = quiclib_buffer_to_vec (buf, &vec, &maps);

  g_return_val_if_fail (n != 0, -1);

  bytes_written = quiclib_ngtcp2_datagram_write (conn, vec, n);

  if (bytes_written > 0 && ticket != NULL) {

    *ticket = conn->datagram_ticket++;
  }

  quiclib_buffer_unmap (&maps);

  return (bytes_written >= 0)?(GST_QUICLIB_ERR_OK):(
      (GstQuicLibError) bytes_written);
}

static void
gst_quiclib_transport_user_class_init (GstQuicLibTransportUserInterface *iface)
{

}

GType
gst_quiclib_transport_user_get_type (void)
{
  static GType type = 0;

  if (g_once_init_enter (&type)) {
    GType _type;
    static const GTypeInfo info = {
        sizeof (GstQuicLibTransportUserInterface),
        NULL,
        NULL,
        (GClassInitFunc) gst_quiclib_transport_user_class_init,
        NULL,
        NULL,
        0,
        0,
        NULL
    };
    _type = g_type_register_static (G_TYPE_INTERFACE,
        "GstQuicLibTransportUser", &info, 0);
    g_type_interface_add_prerequisite (_type, G_TYPE_OBJECT);

    g_once_init_leave (&type, _type);
  }
  return type;
}
