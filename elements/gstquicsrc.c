/*
 * Copyright 2023 British Broadcasting Corporation - Research and Development
 *
 * Author: Sam Hurst <sam.hurst@bbc.co.uk>
 *
 * Based on the GStreamer template repository:
 *  https://gitlab.freedesktop.org/gstreamer/gst-template
 * Copyright (C) 2005 Thomas Vander Stichele <thomas@apestaart.org>
 * Copyright (C) 2005 Ronald S. Bultje <rbultje@ronald.bitfreak.net>
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

/**
 * SECTION:gstquicsrc
 * @title: GstQuicSrc
 * @short description: element used to receive data from a QUIC peer.
 *
 * The quicsrc element is used to receive data from a peer using a QUIC
 * transport connection. It is designed to be used exclusively with a quicdemux
 * element, as src elements may only have a single src pad as per the GStreamer
 * architecture. The buffers flowing downstream from this pad are always tagged
 * with a GstQuicLibStreamMeta or GstQuicLibDatagramMeta if they contain stream
 * frame data or datagram frame data respectively, and quicdemux demultiplexes
 * these onto individual stream/datagram pads.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gst/gst.h>

#include "gstquicsrc.h"
#include "gstquiccommon.h"
#include "gstquicstream.h"
#include "gstquicdatagram.h"
#include "gstquicsignals.h"

GST_DEBUG_CATEGORY_STATIC (gst_quicsrc_debug);
#define GST_CAT_DEFAULT gst_quicsrc_debug

enum
{
  PROP_0,
  PROP_QUIC_ENDPOINT_ENUMS
};

static guint signals[GST_QUICLIB_SIGNALS_MAX];

/* the capabilities of the inputs and outputs.
 *
 * describe the real formats here.
 */
static GstStaticPadTemplate src_factory = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS (QUICLIB_RAW)
    );

static void gst_quicsrc_common_user_interface_init (gpointer g_iface,
    gpointer iface_data);

#define gst_quicsrc_parent_class parent_class
G_DEFINE_TYPE_WITH_CODE (GstQUICSrc, gst_quicsrc, GST_TYPE_PUSH_SRC,
    G_IMPLEMENT_INTERFACE (GST_QUICLIB_COMMON_USER_TYPE,
        gst_quicsrc_common_user_interface_init));

GST_ELEMENT_REGISTER_DEFINE (quicsrc, "quicsrc", GST_RANK_NONE,
    GST_TYPE_QUICSRC);

/*
 * GObject virtual methods
 */
static void gst_quicsrc_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec);
static void gst_quicsrc_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec);

/*
 * GstElement virtual methods
 */
static GstStateChangeReturn gst_quicsrc_change_state (GstElement *elem,
													  GstStateChange t);
/*
 * GstBaseSrc virtual methods
 */
static gboolean gst_quicsrc_query (GstBaseSrc *bsrc, GstQuery *query);
static gboolean gst_quicsrc_get_size (GstBaseSrc *bsrc, guint64 *size);
static gboolean gst_quicsrc_is_seekable (GstBaseSrc *bsrc) { return FALSE; }

/*
 * GstPushSrc virtual methods
 */
static GstFlowReturn gst_quicsrc_create (GstPushSrc *psrc, GstBuffer **outbuf);

static gboolean gst_quicsrc_quiclib_connect (GstQUICSrc *src);
static gboolean gst_quicsrc_quiclib_disconnect (GstQUICSrc *src);

static void quicsrc_stream_flow_control_limited_signal_cb (
    GstElement *signal_src, guint64 stream_id, guint64 max_stream_data,
    gpointer user_data);
static void quicsrc_conn_flow_control_limited_signal_cb (GstElement *signal_src,
    guint64 bytes_in_flight, gpointer user_data);

/* initialize the quicsrc's class */
static void
gst_quicsrc_class_init (GstQUICSrcClass * klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;
  GstElementClass *gstelement_class = (GstElementClass *) klass;
  GstBaseSrcClass *gstbasesrc_class = (GstBaseSrcClass *) klass;
  GstPushSrcClass *gstpushsrc_class = (GstPushSrcClass *) klass;

  gobject_class->set_property = GST_DEBUG_FUNCPTR (gst_quicsrc_set_property);
  gobject_class->get_property = GST_DEBUG_FUNCPTR (gst_quicsrc_get_property);

  gstelement_class->change_state = GST_DEBUG_FUNCPTR (
      gst_quicsrc_change_state);

  gstbasesrc_class->query = GST_DEBUG_FUNCPTR (gst_quicsrc_query);
  gstbasesrc_class->get_size = GST_DEBUG_FUNCPTR (gst_quicsrc_get_size);
  gstbasesrc_class->is_seekable = GST_DEBUG_FUNCPTR (gst_quicsrc_is_seekable);

  gstpushsrc_class->create = GST_DEBUG_FUNCPTR (gst_quicsrc_create);

  gst_quiclib_common_install_endpoint_properties (gobject_class);

  signals[GST_QUICLIB_HANDSHAKE_COMPLETE_SIGNAL] =
    gst_quiclib_handshake_complete_signal_new (klass);
  signals[GST_QUICLIB_STREAM_OPENED_SIGNAL] =
    gst_quiclib_stream_opened_signal_new (klass);
  signals[GST_QUICLIB_STREAM_CLOSED_SIGNAL] =
    gst_quiclib_stream_closed_signal_new (klass);
  signals[GST_QUICLIB_STREAM_FLOW_CONTROL_LIMITED_SIGNAL] =
    gst_quiclib_stream_flow_control_limited_signal_new (klass);
  signals[GST_QUICLIB_CONN_FLOW_CONTROL_LIMITED_SIGNAL] =
    gst_quiclib_conn_flow_control_limited_signal_new (klass);
  signals[GST_QUICLIB_CONN_ERROR_SIGNAL] =
    gst_quiclib_conn_error_signal_new (klass);
  signals[GST_QUICLIB_CONN_CLOSED_SIGNAL] =
    gst_quiclib_conn_closed_signal_new (klass);

  gst_element_class_set_static_metadata (gstelement_class,
      "QUIC message receiver", "Source/Network",
      "Receive data over the network via QUIC transport",
      "Samuel Hurst <sam.hurst@bbc.co.uk>");

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&src_factory));
}

gboolean
quicsrc_user_new_connection (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, GInetSocketAddress *remote,
    const gchar *alpn)
{
  GstQUICSrc *src = GST_QUICSRC (self);
  GstCaps *new_caps;

  GST_DEBUG_OBJECT (src, "New connection from remote %s with ALPN %s",
      g_socket_connectable_to_string (G_SOCKET_CONNECTABLE (remote)), alpn);

  new_caps = gst_caps_new_simple ("application/quic", "alpn", G_TYPE_STRING,
      alpn, NULL);

  if (!gst_pad_peer_query_accept_caps (GST_BASE_SRC (self)->srcpad, new_caps))
  {
    gst_caps_unref (new_caps);
    return FALSE;
  }

  if (src->server_ctx) {
    src->conn = GST_QUICLIB_TRANSPORT_CONNECTION (ctx);

    gst_quiclib_stream_flow_control_limited_signal_connect (src->conn,
        quicsrc_stream_flow_control_limited_signal_cb, (gpointer) src);
    gst_quiclib_conn_flow_control_limited_signal_connect (src->conn,
        quicsrc_conn_flow_control_limited_signal_cb, (gpointer) src);
  }

  gst_base_src_set_caps (GST_BASE_SRC (src), new_caps);

  /* TODO: Send a query for whether to accept this connection? Or is
   * negotiating new caps with the ALPN in it enough?
   */

  return TRUE;
}

gboolean
quicsrc_user_handshake_complete (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, GInetSocketAddress *remote,
    const gchar *alpn, GstQuicLibTransportConnection *conn)
{
  GstQUICSrc *src = GST_QUICSRC (self);

  GST_DEBUG_OBJECT (src, "Handshake complete for %s connection with remote %s",
      alpn, g_socket_connectable_to_string (G_SOCKET_CONNECTABLE (remote)));

  gst_quiclib_handshake_complete_signal_emit (src, G_SOCKET_ADDRESS (remote),
      alpn);

  gst_quiclib_new_handshake_complete_event (GST_BASE_SRC (src)->srcpad,
      G_SOCKET_ADDRESS (remote), alpn);

  if (src->server_ctx) {
    src->conn = GST_QUICLIB_TRANSPORT_CONNECTION (ctx);
  }

  return TRUE;
}

gboolean
quicsrc_user_stream_opened (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, guint64 stream_id)
{
  GstQUICSrc *src = GST_QUICSRC (self);

  gst_quiclib_stream_opened_signal_emit (src, stream_id);

  return gst_quiclib_new_stream_opened_event (GST_BASE_SRC (src)->srcpad,
      stream_id);
}

void
quicsrc_user_stream_closed (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, guint64 stream_id)
{
  GstQUICSrc *src = GST_QUICSRC (self);
  GList *it;
  GstQuicLibStreamMeta *last_meta = NULL;

  GST_TRACE_OBJECT (src, "Stream %lu has closed", stream_id);

  g_mutex_lock (&src->mutex);

  /*
   * Check whether there are outstanding frames for this stream ID waiting to be
   * sent downstream. If there are, set the final flag on the last frame instead
   * of sending the closed event.
   *
   * The stream_closed and stream_data methods should both be called from the
   * QUIC transport thread, so shouldn't need any locking here.
   */
  for (it = g_list_last (src->frames); it != NULL; it = it->prev) {
    GstQuicLibStreamMeta *meta;

    meta = gst_buffer_get_quiclib_stream_meta (GST_BUFFER (it->data));
    g_warn_if_fail (meta);

    if (meta && meta->stream_id == (gint64) stream_id) {
      last_meta = meta;
      break;
    }
  }

  if (last_meta) {
    GST_DEBUG_OBJECT (src, "Setting final flag on last buffer for stream %lu",
        stream_id);
    last_meta->final = TRUE;
  } else {
    GST_DEBUG_OBJECT (src, "Sending stream closed signal and event for stream "
        "%lu", stream_id);

    gst_quiclib_stream_closed_signal_emit (src, stream_id);

    gst_quiclib_new_stream_closed_event (GST_BASE_SRC (src)->srcpad, stream_id);
  }

  g_mutex_unlock (&src->mutex);
}

void
quicsrc_user_stream_data (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, GstBuffer *buf)
{
  GstQUICSrc *src = GST_QUICSRC (self);
  GstQuicLibStreamMeta *meta = gst_buffer_get_quiclib_stream_meta (buf);

  g_assert (meta != NULL);

  GST_DEBUG_OBJECT (src, "Received %ld bytes of stream data for stream %ld",
      meta->length, meta->stream_id);

  gst_buffer_ref (buf);

  g_mutex_lock (&src->mutex);
  src->frames = g_list_append (src->frames, (gpointer) buf);
  g_cond_signal (&src->signal);
  g_mutex_unlock (&src->mutex);
}

void
quicsrc_user_datagram_data (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, GstBuffer *buf)
{
  GstQUICSrc *src = GST_QUICSRC (self);
  GstQuicLibDatagramMeta *meta = gst_buffer_get_quiclib_datagram_meta (buf);

  g_assert (meta != NULL);

  GST_DEBUG_OBJECT (src, "Received QUIC datagram of length %ld", meta->length);

  gst_buffer_ref (buf);

  g_mutex_lock (&src->mutex);
  src->frames = g_list_append (src->frames, (gpointer) buf);
  g_cond_signal (&src->signal);
  g_mutex_unlock (&src->mutex);
}

gboolean
quicsrc_user_connection_error (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, guint64 error)
{
  GstQUICSrc *src = GST_QUICSRC (self);

  gst_quiclib_unref (GST_QUICLIB_TRANSPORT_CONTEXT (src->conn),
      GST_QUICLIB_COMMON_USER (src));

  gst_quiclib_conn_error_signal_emit (src, error);

  /*return gst_quiclib_new_connection_error_event (GST_BASE_SRC (src)->srcpad,
      error);*/
  return FALSE;
}

void
quicsrc_user_connection_closed (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, GInetSocketAddress *remote)
{
  GstQUICSrc *src = GST_QUICSRC (self);
  GstEvent *eos;

  GST_TRACE_OBJECT (src, "Connection closed");

  eos = gst_event_new_eos ();

  gst_pad_push_event (GST_BASE_SRC (src)->srcpad, eos);

  gst_quiclib_conn_closed_signal_emit (src, G_SOCKET_ADDRESS (remote));

  g_cond_signal (&src->signal);

  if (src->conn) {
    gst_quiclib_unref (GST_QUICLIB_TRANSPORT_CONTEXT (src->conn),
        GST_QUICLIB_COMMON_USER (src));
  }
}

void
quicsrc_stream_flow_control_limited_signal_cb (GstElement *signal_src,
    guint64 stream_id, guint64 max_stream_data, gpointer user_data)
{
  GstQUICSrc *src = GST_QUICSRC (user_data);

  gst_quiclib_stream_flow_control_limited_signal_emit (src, stream_id,
      max_stream_data);
}

void
quicsrc_conn_flow_control_limited_signal_cb (GstElement *signal_src,
    guint64 bytes_in_flight, gpointer user_data) {
  GstQUICSrc *src = GST_QUICSRC (user_data);

  gst_quiclib_conn_flow_control_limited_signal_emit (src, bytes_in_flight);
}

static void
gst_quicsrc_common_user_interface_init (gpointer g_iface,
    gpointer iface_data)
{
  GstQuicLibCommonUserInterface *iface = g_iface;

  iface->new_connection = quicsrc_user_new_connection;
  iface->handshake_complete = quicsrc_user_handshake_complete;
  iface->stream_opened = quicsrc_user_stream_opened;
  iface->stream_closed = quicsrc_user_stream_closed;
  iface->stream_data = quicsrc_user_stream_data;
  iface->stream_ackd = NULL;
  iface->datagram_data = quicsrc_user_datagram_data;
  iface->datagram_ackd = NULL;
  iface->connection_error = quicsrc_user_connection_error;
  iface->connection_closed = quicsrc_user_connection_closed;
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad callback functions
 * initialize instance structure
 */
static void
gst_quicsrc_init (GstQUICSrc * src)
{
  src->frames = NULL;

  gst_quiclib_common_init_endpoint_properties (src);

  g_mutex_init (&src->mutex);
  g_cond_init (&src->signal);

  gst_base_src_set_live (GST_BASE_SRC_CAST (src), TRUE);
  gst_base_src_set_format (GST_BASE_SRC_CAST (src), GST_FORMAT_TIME);
  gst_base_src_set_do_timestamp (GST_BASE_SRC_CAST (src), TRUE);
}

static void
gst_quicsrc_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstQUICSrc *src = GST_QUICSRC (object);

  GST_DEBUG_OBJECT (src, "Setting property %s", pspec->name);

  switch (prop_id) {
    case PROP_QUIC_ENDPOINT_COMMON_ENUM_CASES:
    case PROP_QUIC_ENDPOINT_CLIENT_ENUM_CASES:
      if (prop_id == PROP_ALPN) {
        GST_DEBUG_OBJECT (src, "Setting ALPN to %s", g_value_get_string (value));
      } else if (prop_id == PROP_MAX_STREAM_DATA_UNI_REMOTE) {
        GST_DEBUG_OBJECT (src, "Setting max stream data uni to %lu", g_value_get_uint64 (value));
      }
      gst_quiclib_common_set_endpoint_property_checked (src, src->conn, pspec,
          prop_id, value);
      break;
    case PROP_QUIC_ENDPOINT_SERVER_ENUM_CASES:
      if (src->mode == QUICLIB_MODE_SERVER) {
        gst_quiclib_common_set_endpoint_property_checked (src, src->server_ctx,
            pspec, prop_id, value);
      } else {
        GST_WARNING_OBJECT (src,
            "Cannot set server property %s in client mode", pspec->name);
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_quicsrc_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstQUICSrc *src = GST_QUICSRC (object);

  switch (prop_id) {
    case PROP_QUIC_ENDPOINT_COMMON_ENUM_CASES:
    case PROP_QUIC_ENDPOINT_CLIENT_ENUM_CASES:
      gst_quiclib_common_get_endpoint_property_checked (src, src->conn, pspec,
          prop_id, value);
      break;
    case PROP_QUIC_ENDPOINT_SERVER_ENUM_CASES:
      if (src->mode == QUICLIB_MODE_SERVER) {
        gst_quiclib_common_get_endpoint_property_checked (src,
            src->server_ctx, pspec, prop_id, value);
      } else {
        GST_WARNING_OBJECT (src,
            "Cannot get server property %s in client mode", pspec->name);
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

/*
 * GstElement virtual methods
 */
static GstStateChangeReturn
gst_quicsrc_change_state (GstElement *elem, GstStateChange t)
{
  GstQUICSrc *src = GST_QUICSRC (elem);

  GST_TRACE_OBJECT (src, "Changing state from %s to %s",
      gst_element_state_get_name ((t & 0xf8) >> 3),
      gst_element_state_get_name (t & 0x7));

  GstStateChangeReturn rv =
      GST_ELEMENT_CLASS (parent_class)->change_state (elem, t);

  if (t == GST_STATE_CHANGE_READY_TO_PAUSED) {
    if (gst_quicsrc_quiclib_connect (src) == FALSE) {
      return GST_STATE_CHANGE_FAILURE;
    }
    return GST_STATE_CHANGE_NO_PREROLL;
  } else if (t == GST_STATE_CHANGE_PLAYING_TO_PAUSED) {
    if (gst_quicsrc_quiclib_disconnect (src) == FALSE) {
      return GST_STATE_CHANGE_FAILURE;
    }
    g_cond_signal (&src->signal);
    return GST_STATE_CHANGE_SUCCESS;
  }

  return rv;
}

/*
 * GstBaseSrc virtual methods
 */
static gboolean
gst_quicsrc_query (GstBaseSrc *bsrc, GstQuery *query)
{
  GstQUICSrc *src = GST_QUICSRC (bsrc);
  GstStructure *s;

  GST_DEBUG_OBJECT (src, "Received %s query", GST_QUERY_TYPE_NAME (query));

  switch (GST_QUERY_TYPE (query)) {
  case GST_QUERY_CUSTOM:
    g_return_val_if_fail (gst_query_is_writable (query), FALSE);

    s = gst_query_writable_structure (query);

    g_return_val_if_fail (s, FALSE);

    if (gst_structure_has_name (s, QUICLIB_CONNECTION_STATE)) {
      GstQUICMode mode;
      GstQuicLibTransportState state;
      GSocketAddress *local_addr, *peer_addr;

      GST_LOG_OBJECT (src, "Received connection state query");

      if (src->conn == NULL) {

        g_return_val_if_fail (gst_query_fill_quiclib_conn_state (query,
            (src->server_ctx)?(QUICLIB_MODE_SERVER):(QUICLIB_MODE_CLIENT),
            QUIC_STATE_NONE, NULL, NULL), FALSE);
        break;
      }

      mode = gst_quiclib_transport_get_mode (
          GST_QUICLIB_TRANSPORT_CONTEXT (src->conn));
      state = gst_quiclib_transport_get_state (
          GST_QUICLIB_TRANSPORT_CONTEXT (src->conn));
      local_addr = G_SOCKET_ADDRESS (
          gst_quiclib_transport_get_local (src->conn));
      peer_addr = G_SOCKET_ADDRESS (gst_quiclib_transport_get_peer (src->conn));

      g_return_val_if_fail (gst_query_fill_quiclib_conn_state (query, mode,
          state, local_addr, peer_addr), FALSE);

    } else if (gst_structure_has_name (s, QUICLIB_STREAM_CLOSE)) {
      guint64 stream_id, reason;

      GST_LOG_OBJECT (src, "Received stream close query");

      g_return_val_if_fail (src->conn, FALSE);

      g_return_val_if_fail (gst_structure_get_uint64 (s,
          QUICLIB_STREAMID_KEY, &stream_id), FALSE);

      if (gst_structure_get_uint64 (s, QUICLIB_CANCEL_REASON, &reason) == FALSE) {
        reason = 0x102;
      }

      GST_LOG_OBJECT (src, "Asking transport to close stream %lu with reason "
          "%lu", stream_id, reason);

      return gst_quiclib_transport_close_stream (src->conn, stream_id, reason);
    } else if (gst_structure_has_name (s, QUICLIB_STREAM_STATE)) {
      guint64 stream_id;
      GstQuicLibStreamState state;
      gchar *statestr;

      GST_LOG_OBJECT (src, "Received stream state query");

      g_return_val_if_fail (gst_structure_get_uint64 (s, QUICLIB_STREAMID_KEY,
          &stream_id), FALSE);

      state = gst_quiclib_transport_stream_state (src->conn, stream_id);
      statestr = g_enum_to_string (quiclib_stream_status_get_type (), state);

      GST_LOG_OBJECT (src, "Return stream state query for stream %lu with "
          "state %s", stream_id, statestr);

      g_free (statestr);

      g_return_val_if_fail (gst_query_fill_quiclib_stream_state (query, state),
          FALSE);
    } else {
      GST_ERROR_OBJECT (src, "Unknown or unsupported custom query type: %s",
          gst_structure_get_name (s));
      return FALSE;
    }
    break;
  default:
    return GST_BASE_SRC_CLASS (parent_class)->query (bsrc, query);
  }

  return TRUE;
}

static gboolean
gst_quicsrc_get_size (GstBaseSrc *bsrc, guint64 *size)
{
  GstQUICSrc *src = GST_QUICSRC (bsrc);

  *size = G_MAXUINT64;

  GST_DEBUG_OBJECT (src, "Returning size of %lu", *size);

  return TRUE;
}

/*
 * GstPushSrc virtual methods
 */
static GstFlowReturn
gst_quicsrc_create (GstPushSrc *psrc, GstBuffer **outbuf)
{
  GstQUICSrc *src = GST_QUICSRC (psrc);

  g_mutex_lock (&src->mutex);

  if (src->frames == NULL) {
    GstState current, pending;

    GST_DEBUG_OBJECT (src, "Waiting for frames from QUICLIB...");
    g_cond_wait (&src->signal, &src->mutex);

    gst_element_get_state (GST_ELEMENT (src), &current, &pending, 0);
    if (current != GST_STATE_PLAYING) {
      return GST_FLOW_OK;
    }
  }

  if (GST_PAD_IS_EOS (GST_BASE_SRC (src)->srcpad)) {
    GST_DEBUG_OBJECT (src, "Src pad is EOS");
    return GST_FLOW_EOS;
  }

  *outbuf = GST_BUFFER (src->frames->data);
  /* pop the front off the list */
  src->frames = g_list_delete_link (src->frames, src->frames);

  g_mutex_unlock (&src->mutex);

  GST_DEBUG_OBJECT (src, "Pushing buffer of size %ld bytes with PTS %"
      GST_TIME_FORMAT ", DTS %" GST_TIME_FORMAT, gst_buffer_get_size (*outbuf),
      GST_TIME_ARGS ((*outbuf)->pts), GST_TIME_ARGS ((*outbuf)->dts));

  return GST_FLOW_OK;
}

static gboolean
gst_quicsrc_quiclib_connect (GstQUICSrc *src)
{
  GObject *obj;

  gst_quicsrc_quiclib_disconnect (src);

  switch (src->mode) {
  case QUICLIB_MODE_CLIENT:
    src->conn = gst_quiclib_get_client (GST_QUICLIB_COMMON_USER (src),
        src->location, src->alpn);
    if (src->conn == NULL) return FALSE;

    obj = G_OBJECT (src->conn);
    break;
  case QUICLIB_MODE_SERVER:
    src->server_ctx = gst_quiclib_get_server (GST_QUICLIB_COMMON_USER (src),
        src->location, src->alpn, src->privkey_location, src->cert_location,
        src->sni);
    if (src->server_ctx == NULL) return FALSE;

    obj = G_OBJECT (src->server_ctx);
    break;
  }

  g_object_set (obj,
      PROP_MAX_STREAMS_BIDI_REMOTE_SHORTNAME, src->max_streams_bidi_remote_init,
      PROP_MAX_STREAMS_UNI_REMOTE_SHORTNAME, src->max_streams_uni_remote_init,
      PROP_MAX_STREAM_DATA_BIDI_REMOTE_SHORTNAME,
      src->max_stream_data_bidi_remote_init,
      PROP_MAX_STREAM_DATA_UNI_REMOTE_SHORTNAME,
      src->max_stream_data_uni_remote_init,
      PROP_MAX_DATA_REMOTE_SHORTNAME, src->max_data_remote_init,
      PROP_ENABLE_DATAGRAM_SHORTNAME, src->enable_datagram, NULL);

  if (gst_quiclib_transport_get_state (GST_QUICLIB_TRANSPORT_CONTEXT (obj))
      == QUIC_STATE_NONE) {
    switch (src->mode) {
      case QUICLIB_MODE_CLIENT:
        if (!gst_quiclib_transport_client_connect (src->conn)) {
          GST_ERROR_OBJECT (src,
              "Couldn't open client connection with location %s",
              src->location);
          gst_quiclib_unref (GST_QUICLIB_TRANSPORT_CONTEXT (src->conn),
              GST_QUICLIB_COMMON_USER (src));
          return FALSE;
        }
        break;
      case QUICLIB_MODE_SERVER:
        if (!gst_quiclib_transport_server_listen (src->server_ctx)) {
          GST_ERROR_OBJECT (src, "Couldn't listen on server address %s",
              src->location);
          gst_quiclib_unref (GST_QUICLIB_TRANSPORT_CONTEXT (src->server_ctx),
              GST_QUICLIB_COMMON_USER (src));
          return FALSE;
        }
        break;
    }
  }
  return TRUE;
}

static gboolean
gst_quicsrc_quiclib_disconnect (GstQUICSrc *src)
{
  if (src->conn != NULL) {
    return gst_quiclib_transport_disconnect (src->conn, FALSE,
        QUICLIB_CLOSE_NO_ERROR) == 0;
  }
  return FALSE;
}

/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
static gboolean
quicsrc_init (GstPlugin * quicsrc)
{
  /* debug category for filtering log messages
   *
   * exchange the string 'Template quicsrc' with your description
   */
  GST_DEBUG_CATEGORY_INIT (gst_quicsrc_debug, "quicsrc",
      0, "Template quicsrc");

  return GST_ELEMENT_REGISTER (quicsrc, quicsrc);
}

/* PACKAGE: this is usually set by meson depending on some _INIT macro
 * in meson.build and then written into and defined in config.h, but we can
 * just set it ourselves here in case someone doesn't use meson to
 * compile this code. GST_PLUGIN_DEFINE needs PACKAGE to be defined.
 */
#ifndef PACKAGE
#define PACKAGE "quicsrc"
#endif

/* gstreamer looks for this structure to register quicsrcs
 *
 * exchange the string 'Template quicsrc' with your quicsrc description
 */
GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    quicsrc,
    "quicsrc",
    quicsrc_init,
    PACKAGE_VERSION, GST_LICENSE, GST_PACKAGE_NAME, GST_PACKAGE_ORIGIN)

