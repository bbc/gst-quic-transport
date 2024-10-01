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
 * SECTION:gstquicsink
 * @title: GstQuicSink
 * @short description: element used to send data to a QUIC peer.
 *
 * The quicsink element is used to receive data from a peer using a QUIC
 * transport connection. It is designed to be used exclusively with a quicmux
 * element, as sink elements may only have a single sink pad as per the
 * GStreamer architecture. The buffers flowing to this element from upstream
 * must always be tagged with GstQuicLibStreamMeta if they contain stream frame
 * data or GstQuicLibDatagramMeta if they contain datagram frame data, which
 * quicmux is guaranteed to always do.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gst/gst.h>

#include "gstquicsink.h"
#include "gstquictransport.h"
#include "gstquicsignals.h"
#include "gstquicstream.h"

GST_DEBUG_CATEGORY_STATIC (gst_quicsink_debug);
#define GST_CAT_DEFAULT gst_quicsink_debug

enum
{
  PROP_0,
  PROP_QUIC_ENDPOINT_ENUMS,
  PROP_QUIC_CONNECTION_CTX
};

static guint signals[GST_QUICLIB_SIGNALS_MAX];

/* the capabilities of the inputs and outputs.
 *
 * describe the real formats here.
 */
static GstStaticPadTemplate sink_factory = GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS (QUICLIB_RAW)
    );

static void gst_quicsink_common_user_interface_init (gpointer g_iface,
    gpointer iface_data);

#define gst_quicsink_parent_class parent_class
G_DEFINE_TYPE_WITH_CODE (GstQuicSink, gst_quicsink, GST_TYPE_BASE_SINK,
    G_IMPLEMENT_INTERFACE (GST_QUICLIB_COMMON_USER_TYPE,
        gst_quicsink_common_user_interface_init));

GST_ELEMENT_REGISTER_DEFINE (quicsink, "quicsink", GST_RANK_NONE,
    GST_TYPE_QUICSINK);

static void gst_quicsink_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec);
static void gst_quicsink_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec);

static GstStateChangeReturn gst_quicsink_change_state (GstElement *elem,
    GstStateChange t);

static gboolean gst_quicsink_elem_query (GstElement *parent, GstQuery *query);
static gboolean gst_quicsink_query (GstBaseSink * parent, GstQuery * query);
static GstFlowReturn gst_quicsink_render (GstBaseSink * sink,
    GstBuffer * buffer);

static gboolean gst_quicsink_quiclib_listen (GstQuicSink *sink);
static gboolean gst_quicsink_quiclib_connect (GstQuicSink *sink);
static gboolean gst_quicsink_quiclib_disconnect (GstQuicSink *sink);
static gboolean gst_quicsink_quiclib_stop_listen (GstQuicSink *sink);

static gboolean
gst_quicsink_quiclib_listen (GstQuicSink *sink)
{
  g_return_val_if_fail (sink->mode == QUICLIB_MODE_SERVER, FALSE);

  gst_quicsink_quiclib_stop_listen (sink);

  g_mutex_lock (&sink->mutex);

  GST_TRACE_OBJECT (sink, "Opening listening port on %s", sink->location);

  sink->server_ctx = gst_quiclib_get_server (GST_QUICLIB_COMMON_USER (sink),
      sink->location, sink->alpn, sink->privkey_location, sink->cert_location,
      sink->sni);

  g_object_set (sink->server_ctx,
      PROP_MAX_STREAMS_BIDI_REMOTE_SHORTNAME,
      sink->max_streams_bidi_remote_init,
      PROP_MAX_STREAMS_UNI_REMOTE_SHORTNAME, sink->max_streams_uni_remote_init,
      PROP_MAX_STREAM_DATA_BIDI_REMOTE_SHORTNAME,
      sink->max_stream_data_bidi_remote_init,
      PROP_MAX_STREAM_DATA_UNI_REMOTE_SHORTNAME,
      sink->max_stream_data_uni_remote_init,
      PROP_MAX_DATA_REMOTE_SHORTNAME, sink->max_data_remote_init,
      PROP_ENABLE_DATAGRAM_SHORTNAME, sink->enable_datagram, NULL);

  if (gst_quiclib_transport_get_state (
        GST_QUICLIB_TRANSPORT_CONTEXT (sink->server_ctx)) == QUIC_STATE_NONE) {
    if (!gst_quiclib_transport_server_listen (sink->server_ctx)) {
      GST_ERROR_OBJECT (sink, "Couldn't listen on server address %s",
          sink->location);
      gst_quiclib_unref (GST_QUICLIB_TRANSPORT_CONTEXT (sink->conn),
          GST_QUICLIB_COMMON_USER (sink));
    }
  }

  g_mutex_unlock (&sink->mutex);

  return sink->server_ctx != NULL;
}

static gboolean
gst_quicsink_quiclib_connect (GstQuicSink *sink)
{
  g_return_val_if_fail (sink->mode == QUICLIB_MODE_CLIENT, FALSE);

  gst_quicsink_quiclib_disconnect (sink);

  g_mutex_lock (&sink->mutex);

  GST_TRACE_OBJECT (sink, "Connecting to %s with ALPN %s", sink->location,
      sink->alpn);
  sink->conn = gst_quiclib_get_client (GST_QUICLIB_COMMON_USER (sink),
      sink->location, sink->alpn);

  g_object_set (sink->conn,
      PROP_MAX_STREAMS_BIDI_REMOTE_SHORTNAME,
      sink->max_streams_bidi_remote_init,
      PROP_MAX_STREAMS_UNI_REMOTE_SHORTNAME, sink->max_streams_uni_remote_init,
      PROP_MAX_STREAM_DATA_BIDI_REMOTE_SHORTNAME,
      sink->max_stream_data_bidi_remote_init,
      PROP_MAX_STREAM_DATA_UNI_REMOTE_SHORTNAME,
      sink->max_stream_data_uni_remote_init,
      PROP_MAX_DATA_REMOTE_SHORTNAME, sink->max_data_remote_init,
      PROP_ENABLE_DATAGRAM_SHORTNAME, sink->enable_datagram, NULL);

  if (gst_quiclib_transport_get_state (
        GST_QUICLIB_TRANSPORT_CONTEXT (sink->conn)) == QUIC_STATE_NONE) {
    if (!gst_quiclib_transport_client_connect (sink->conn)) {
      GST_ERROR_OBJECT (sink, "Couldn't open client connection with location %s",
          sink->location);
      gst_quiclib_unref (GST_QUICLIB_TRANSPORT_CONTEXT (sink->conn),
          GST_QUICLIB_COMMON_USER (sink));
    }
  }

  g_mutex_unlock (&sink->mutex);

  return sink->conn != NULL;
}

static gboolean
gst_quicsink_quiclib_disconnect (GstQuicSink *sink)
{
  g_mutex_lock (&sink->mutex);
  GST_TRACE_OBJECT (sink, "Disconnect called - %sactive connection",
      (sink->conn)?(""):("no "));
  if (sink->conn != NULL) {
    gst_quiclib_unref (GST_QUICLIB_TRANSPORT_CONTEXT (sink->conn),
        GST_QUICLIB_COMMON_USER (sink));
    sink->conn = NULL;
    g_mutex_unlock (&sink->mutex);
    return TRUE;
  }

  g_mutex_unlock (&sink->mutex);

  return FALSE;
}

static gboolean
gst_quicsink_quiclib_stop_listen (GstQuicSink *sink)
{
  g_return_val_if_fail (sink->mode == QUICLIB_MODE_SERVER, FALSE);

  gst_quicsink_quiclib_disconnect (sink);

  g_mutex_lock (&sink->mutex);

  GST_TRACE_OBJECT (sink, "Stop listen called - %sactive server",
        (sink->server_ctx)?(""):("no "));

  if (sink->server_ctx != NULL) {
    gst_quiclib_unref (GST_QUICLIB_TRANSPORT_CONTEXT (sink->server_ctx),
            GST_QUICLIB_COMMON_USER (sink));
    sink->server_ctx = NULL;
    g_mutex_unlock (&sink->mutex);
    return TRUE;
  }
  g_mutex_unlock (&sink->mutex);
  return FALSE;
}

/* GObject vmethod implementations */

/* initialize the quicsink's class */
static void
gst_quicsink_class_init (GstQuicSinkClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class;
  GstBaseSinkClass *gstbasesink_class;

  gobject_class = (GObjectClass *) klass;
  gstelement_class = (GstElementClass *) klass;
  gstbasesink_class = (GstBaseSinkClass *) klass;

  gobject_class->set_property = gst_quicsink_set_property;
  gobject_class->get_property = gst_quicsink_get_property;

  gstelement_class->change_state = gst_quicsink_change_state;
  gstelement_class->query = gst_quicsink_elem_query;

  gstbasesink_class->render = gst_quicsink_render;
  gstbasesink_class->query = gst_quicsink_query;

  gst_quiclib_common_install_endpoint_properties (gobject_class);

  g_object_class_install_property (gobject_class, PROP_QUIC_CONNECTION_CTX,
      g_param_spec_pointer ("quic-ctx", "QUIC Transport Context",
          "Underlying QUIC transport context", G_PARAM_READABLE));

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
        "QUIC message sender", "Source/Network",
        "Send data over the network via QUIC transport",
        "Samuel Hurst <sam.hurst@bbc.co.uk>");

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&sink_factory));
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad callback functions
 * initialize instance structure
 */
static void
gst_quicsink_init (GstQuicSink * sink)
{
  gst_quiclib_common_init_endpoint_properties (sink);

  g_mutex_init (&sink->mutex);
  g_cond_init (&sink->ctx_change);
}

static void
gst_quicsink_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstQuicSink *sink = GST_QUICSINK (object);

  switch (prop_id) {
    case PROP_QUIC_ENDPOINT_COMMON_ENUM_CASES:
    case PROP_QUIC_ENDPOINT_CLIENT_ENUM_CASES:
      if (prop_id == PROP_ALPN) {
        GST_DEBUG_OBJECT (sink, "Setting ALPN to %s", g_value_get_string (value));
      } else if (prop_id == PROP_MAX_STREAM_DATA_UNI_REMOTE) {
        GST_DEBUG_OBJECT (sink, "Setting max stream data uni to %lu", g_value_get_uint64 (value));
      }
      gst_quiclib_common_set_endpoint_property_checked (sink, sink->conn, pspec,
          prop_id, value);
      break;
    case PROP_QUIC_ENDPOINT_SERVER_ENUM_CASES:
      if (sink->mode == QUICLIB_MODE_SERVER) {
        g_mutex_lock (&sink->mutex);
        gst_quiclib_common_set_endpoint_property_checked (sink,
            sink->server_ctx, pspec, prop_id, value);
        g_mutex_unlock (&sink->mutex);
      } else {
        GST_WARNING_OBJECT (sink,
            "Cannot set server property %s in client mode", pspec->name);
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_quicsink_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstQuicSink *sink = GST_QUICSINK (object);

  switch (prop_id) {
    case PROP_QUIC_ENDPOINT_COMMON_ENUM_CASES:
    case PROP_QUIC_ENDPOINT_CLIENT_ENUM_CASES:
      gst_quiclib_common_get_endpoint_property_checked (sink, sink->conn, pspec,
          prop_id, value);
      break;
    case PROP_QUIC_ENDPOINT_SERVER_ENUM_CASES:
      if (sink->mode == QUICLIB_MODE_SERVER) {
        g_mutex_lock (&sink->mutex);
        gst_quiclib_common_get_endpoint_property_checked (sink,
            sink->server_ctx, pspec, prop_id, value);
        g_mutex_unlock (&sink->mutex);
      } else {
        GST_WARNING_OBJECT (sink,
            "Cannot get server property %s in client mode", pspec->name);
      }
      break;
    case PROP_QUIC_CONNECTION_CTX:
      g_value_set_pointer (value, (gpointer) sink->conn);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

/* GstElement vmethod implementations */
static GstStateChangeReturn
gst_quicsink_change_state (GstElement *elem, GstStateChange t)
{
  GstQuicSink *sink = GST_QUICSINK (elem);

  GST_TRACE_OBJECT (sink, "Changing state from %s to %s",
      gst_element_state_get_name ((t & 0xf8) >> 3),
      gst_element_state_get_name (t & 0x4));

  GstStateChangeReturn rv =
      GST_ELEMENT_CLASS (parent_class)->change_state (elem, t);

  switch (t) {
  case GST_STATE_CHANGE_READY_TO_PAUSED:
    switch (sink->mode) {
    case QUICLIB_MODE_SERVER:
      if (gst_quicsink_quiclib_listen (sink) == FALSE) {
        return GST_STATE_CHANGE_FAILURE;
      }
      break;
    case QUICLIB_MODE_CLIENT:
      if (gst_quicsink_quiclib_connect (sink) == FALSE) {
        return GST_STATE_CHANGE_FAILURE;
      }
      break;
    }
    return GST_STATE_CHANGE_NO_PREROLL;
  case GST_STATE_CHANGE_PLAYING_TO_PAUSED:
    if (gst_quicsink_quiclib_disconnect (sink) == FALSE) {
      return GST_STATE_CHANGE_FAILURE;
    }
    break;
  case GST_STATE_CHANGE_PAUSED_TO_READY:
    if (sink->mode == QUICLIB_MODE_SERVER) {
      gst_quicsink_quiclib_stop_listen (sink);
    }
    break;
  default:
    break;
  }

  return rv;
}

static gboolean
gst_quicsink_elem_query (GstElement *parent, GstQuery *query)
{
  return gst_quicsink_query (GST_BASE_SINK (parent), query);
}

static gboolean
gst_quicsink_query (GstBaseSink * parent, GstQuery * query)
{
  GstQuicSink *sink = GST_QUICSINK (parent);
  const gchar *query_type = GST_QUERY_TYPE_NAME (query);
  GstStructure *s;

  switch (GST_QUERY_TYPE (query)) {
  case GST_QUERY_CUSTOM:
    g_return_val_if_fail (gst_query_is_writable (query), FALSE);

    s = gst_query_writable_structure (query);

    g_return_val_if_fail (s, FALSE);

    /*
     * TODO: This seems inefficient to do gst_structure_has_name every time -
     * maybe make this a generic sequence that
     */

    if (gst_structure_has_name (s, QUICLIB_CONNECTION_STATE)) {
      GstQUICMode mode;
      GstQuicLibTransportState state;
      gchar *statestr;
      GSocketAddress *local_addr, *peer_addr;
      gchar *addrstr;

      GST_LOG_OBJECT (sink, "Received connection state query");

      g_mutex_lock (&sink->mutex);
      if (sink->conn == NULL) {
        gst_structure_set (s, QUICLIB_CONNECTION_STATE,
            gst_quiclib_transport_state_get_type (), QUIC_STATE_NONE,
            NULL);
        GST_WARNING_OBJECT (sink, "No QUIC connection to query the state of");
        g_mutex_unlock (&sink->mutex);
        break;
      }

      mode = gst_quiclib_transport_get_mode (
          GST_QUICLIB_TRANSPORT_CONTEXT (sink->conn));
      state = gst_quiclib_transport_get_state (
          GST_QUICLIB_TRANSPORT_CONTEXT (sink->conn));
      statestr = g_enum_to_string (gst_quiclib_transport_state_get_type (),
          state);
      local_addr =
          G_SOCKET_ADDRESS (gst_quiclib_transport_get_local (sink->conn));
      peer_addr =
          G_SOCKET_ADDRESS (gst_quiclib_transport_get_peer (sink->conn));
      addrstr = g_socket_connectable_to_string (
          G_SOCKET_CONNECTABLE (peer_addr));

      g_mutex_unlock (&sink->mutex);

      GST_LOG_OBJECT (sink, "Returning connection state query with state %s"
          " for connection with peer %s", statestr, addrstr);

      g_free (statestr);
      g_free (addrstr);

      g_return_val_if_fail (gst_query_fill_quiclib_conn_state (query, mode,
          state, local_addr, peer_addr), FALSE);

      break;
    } else if (gst_structure_has_name (s, QUICLIB_STREAM_OPEN)) {
      GstQuicLibStreamType type;
      GstQuicLibStreamState state = QUIC_STREAM_OPEN;
      gchar *statestr;
      gint64 stream_id = -1;

      GST_LOG_OBJECT (sink, "Received stream open query");

      if (sink->conn == NULL) {
        GST_WARNING_OBJECT (sink,
            "No QUIC connection to open a new stream for");
        state = QUIC_STREAM_ERROR_CONNECTION;
      } else {
        g_mutex_lock (&sink->mutex);
        g_return_val_if_fail (gst_structure_get_enum (s, QUICLIB_STREAM_TYPE,
            quiclib_stream_type_get_type (), (gint *) &type), FALSE);

        stream_id = gst_quiclib_transport_open_stream (sink->conn,
            type == QUIC_STREAM_BIDI, NULL);

        g_mutex_unlock (&sink->mutex);

        switch (stream_id) {
        case GST_QUICLIB_ERR:
          state = QUIC_STREAM_ERROR_CONNECTION;
          break;
        case GST_QUICLIB_ERR_STREAM_ID_BLOCKED:
          state = QUIC_STREAM_ERROR_MAX_STREAMS;
          break;
        default:
          break;
        }

        if (state == QUIC_STREAM_OPEN && type == QUIC_STREAM_UNI) {
          state |= QUIC_STREAM_CLOSED_READING;
        }
      }

      statestr = g_enum_to_string (quiclib_stream_status_get_type (), state);

      if (stream_id >= 0) {
        GST_LOG_OBJECT (sink, "Returning stream open query with new stream ID "
            "%ld and state %s", stream_id, statestr);
      } else {
        GST_WARNING_OBJECT (sink, "Couldn't open new stream, state %s",
            statestr);
      }

      g_free (statestr);

      g_return_val_if_fail (gst_query_fill_new_quiclib_stream (query,
          stream_id, state), FALSE);
    } else if (gst_structure_has_name (s, QUICLIB_STREAM_CLOSE)) {
      guint64 stream_id, reason;
      gboolean rv;

      GST_LOG_OBJECT (sink, "Received stream close query");

      g_mutex_lock (&sink->mutex);

      g_return_val_if_fail (sink->conn, FALSE);

      g_return_val_if_fail (gst_structure_get_uint64 (s,
          QUICLIB_STREAMID_KEY, &stream_id), FALSE);

      if (gst_structure_get_uint64 (s, QUICLIB_CANCEL_REASON, &reason)
          == FALSE) {
        reason = 0;
      }

      GST_LOG_OBJECT (sink, "Asking transport to close stream %lu with reason "
          "%lu", stream_id, reason);

      rv = gst_quiclib_transport_close_stream (sink->conn, stream_id,
          reason);

      g_mutex_unlock (&sink->mutex);
      
      return rv;
    } else if (gst_structure_has_name (s, QUICLIB_STREAM_STATE)) {
      guint64 stream_id;
      GstQuicLibStreamState state;
      gchar *statestr;

      GST_LOG_OBJECT (sink, "Received stream state query");

      g_mutex_lock (&sink->mutex);

      g_return_val_if_fail (gst_structure_get_uint64 (s, QUICLIB_STREAMID_KEY,
          &stream_id), FALSE);

      state = gst_quiclib_transport_stream_state (sink->conn, stream_id);
      statestr = g_enum_to_string (quiclib_stream_status_get_type (), state);

      g_mutex_unlock (&sink->mutex);

      GST_LOG_OBJECT (sink, "Return stream state query for stream %lu with "
          "state %s", stream_id, statestr);

      g_free (statestr);

      g_return_val_if_fail (gst_query_fill_quiclib_stream_state (query, state),
          FALSE);
    } else {
      GST_ERROR_OBJECT (sink, "Unknown custom query type: %s",
          gst_structure_get_name (s));
      return FALSE;
    }
    break;
  default:
    GST_LOG_OBJECT (sink, "Received %s query, passing to base class",
        query_type);
    return GST_ELEMENT_CLASS (parent_class)->query (GST_ELEMENT (parent),
        query);
    break;
  }

  return TRUE;
}

/*
 * Receive a buffer and dispatch to the QUIC library
 */
static GstFlowReturn
gst_quicsink_render (GstBaseSink * sink, GstBuffer * buffer)
{
  GstQuicSink *quicsink = GST_QUICSINK (sink);
  gsize sent = 0, buf_size = gst_buffer_get_size (buffer);

  GST_DEBUG_OBJECT (quicsink, "Received buffer of size %lu", buf_size);

  g_mutex_lock (&quicsink->mutex);
  while (quicsink->conn == NULL || gst_quiclib_transport_get_state (
        GST_QUICLIB_TRANSPORT_CONTEXT (quicsink->conn)) != QUIC_STATE_OPEN) {
    /*
     * TODO: Drop DATAGRAMs? Return error state? What's the right thing to do
     * here? For now, this just blocks the pipeline, which is probably not
     * strictly correct.
     */
    GST_DEBUG_OBJECT (quicsink, "Waiting for connection to be ready...");
    g_cond_wait (&quicsink->ctx_change, &quicsink->mutex);
  }

  while (sent < buf_size) {
    gssize b_sent = 0;
    GstQuicLibError err = gst_quiclib_transport_send_buffer (quicsink->conn,
        buffer, &b_sent);

    GST_TRACE_OBJECT (quicsink,
        "Send buffer returned %d (%s) with %lu bytes sent", err,
        gst_quiclib_error_as_string (err), b_sent);
        
    if (err != GST_QUICLIB_ERR_OK) {
      g_mutex_unlock (&quicsink->mutex);
      switch (err) {
        case GST_QUICLIB_ERR:
          return GST_FLOW_ERROR;
        case GST_QUICLIB_ERR_CONN_DATA_BLOCKED:
          return GST_FLOW_QUIC_BLOCKED;
        case GST_QUICLIB_ERR_STREAM_ID_BLOCKED:
        case GST_QUICLIB_ERR_STREAM_DATA_BLOCKED:
        case GST_QUICLIB_ERR_STREAM_CLOSED:
        {
          GstQuicLibStreamMeta *stream_meta =
              gst_buffer_get_quiclib_stream_meta (buffer);

          g_assert (stream_meta);

          switch (err) {
            case GST_QUICLIB_ERR_STREAM_ID_BLOCKED:
              GST_ERROR_OBJECT (quicsink, "Could not send buffer of size %lu"
                  "on stream ID %lu, stream ID is blocked by MAX_%s_STREAMS",
                  buf_size, stream_meta->stream_id,
                  (stream_meta->stream_id & 0x2)?("UNI"):("BIDI"));
              return GST_FLOW_ERROR;
            case GST_QUICLIB_ERR_STREAM_DATA_BLOCKED:
              GST_ERROR_OBJECT (quicsink, "Could not send buffer of size %lu "
                  "on stream ID %lu, stream blocked by flow control", buf_size,
                  stream_meta->stream_id);
              return GST_FLOW_ERROR;
            case GST_QUICLIB_ERR_STREAM_CLOSED:
              GST_ERROR_OBJECT (quicsink, "Could not send buffer of size %lu "
                  "on stream ID %ld, stream closed for writing", buf_size,
                  stream_meta->stream_id);
              break;
            default:
          }
          return GST_FLOW_QUIC_STREAM_CLOSED;
        }
        case GST_QUICLIB_ERR_PACKET_NUM_EXHAUSTED:
          GST_ERROR_OBJECT (quicsink, "QUIC connection has exhausted its "
              "packet number space, this connection is done!");
          return GST_FLOW_EOS;
        case GST_QUICLIB_ERR_EXTENSION_NOT_SUPPORTED:
          GST_ERROR_OBJECT (quicsink,
              "Required extension to send buffer not supported");
          return GST_FLOW_QUIC_EXTENSION_NOT_SUPPORTED;
        default:
          GST_ERROR_OBJECT (quicsink,
              "QuicLib returned unknown return error code %d", err);
          return GST_FLOW_ERROR;
      }
    }
    
    sent += (gsize) b_sent;
    GST_TRACE_OBJECT (quicsink, "Sent %ld bytes of %lu, %lu sent total", b_sent,
        buf_size, sent);
  }

  g_mutex_unlock (&quicsink->mutex);

  GST_DEBUG_OBJECT (quicsink, "Buffer sent");

  return GST_FLOW_OK;
}

static gboolean
quicsink_user_new_connection (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, GInetSocketAddress *remote,
    const gchar *alpn)
{
  GstQuicSink *quicsink = GST_QUICSINK (self);
  gchar *addr = g_socket_connectable_to_string (G_SOCKET_CONNECTABLE (remote));
  GstQuery *query;

  GST_TRACE_OBJECT (quicsink, "New %s connection with peer %s", alpn, addr);

  query = gst_query_new_quiclib_client_connect (G_SOCKET_ADDRESS (remote), alpn);

  return gst_pad_query (gst_pad_get_peer (GST_BASE_SINK (quicsink)->sinkpad),
      query);
}

static gboolean
quicsink_user_handshake_complete (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, GInetSocketAddress *remote,
    const gchar *alpn, GstQuicLibTransportConnection *conn)
{
  GstQuicSink *quicsink = GST_QUICSINK (self);
  gchar *addr = g_socket_connectable_to_string (G_SOCKET_CONNECTABLE (remote));

  GST_TRACE_OBJECT (quicsink, "Handshake complete for %s connection with %s",
      alpn, addr);

  g_mutex_lock (&quicsink->mutex);

  g_free (addr);

  quicsink->conn = conn;

  g_cond_signal (&quicsink->ctx_change);
  g_mutex_unlock (&quicsink->mutex);

  gst_element_set_state (GST_ELEMENT (quicsink), GST_STATE_PLAYING);

  gst_quiclib_handshake_complete_signal_emit (quicsink,
      G_SOCKET_ADDRESS (remote), alpn);

  return gst_quiclib_new_handshake_complete_event (
      GST_BASE_SINK (quicsink)->sinkpad, G_SOCKET_ADDRESS (remote), alpn);
}

static gboolean
quicsink_user_stream_opened (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, guint64 stream_id)
{
  GstQuicSink *quicsink = GST_QUICSINK (self);

  GST_TRACE_OBJECT (quicsink, "Stream %lu opened", stream_id);

  g_cond_signal (&quicsink->ctx_change);

  return gst_quiclib_new_stream_opened_event (
      GST_BASE_SINK (quicsink)->sinkpad, stream_id);
}

static void
quicsink_user_stream_closed (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, guint64 stream_id)
{
  GstQuicSink *quicsink = GST_QUICSINK (self);

  GST_TRACE_OBJECT (quicsink, "Stream %lu closed", stream_id);

  g_cond_signal (&quicsink->ctx_change);

  gst_quiclib_new_stream_closed_event (GST_BASE_SINK (quicsink)->sinkpad,
      stream_id);
}

static void
quicsink_user_stream_ackd (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, guint64 stream_id, gsize ackd_offset)
{
  GstQuicSink *quicsink = GST_QUICSINK (self);

  GST_TRACE_OBJECT (quicsink, "Acknowledged up to %ld on stream %lu",
      ackd_offset, stream_id);
}

static void
quicsink_user_datagram_ackd (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, GstBuffer *ackd_datagram)
{
  GstQuicSink *quicsink = GST_QUICSINK (self);

  GST_TRACE_OBJECT (quicsink, "TODO: Datagram %" GST_PTR_FORMAT " acknowledged",
      ackd_datagram);
}

static gboolean
quicsink_user_connection_error (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, guint64 error)
{
  GstQuicSink *quicsink = GST_QUICSINK (self);

  g_cond_signal (&quicsink->ctx_change);

  GST_TRACE_OBJECT (quicsink, "Connection error: %lu", error);
  return FALSE;
}

static void
quicsink_user_connection_closed (GstQuicLibCommonUser *self,
    GstQuicLibTransportContext *ctx, GInetSocketAddress *remote)
{
  GstQuicSink *quicsink = GST_QUICSINK (self);
  gchar *addr = g_socket_connectable_to_string (G_SOCKET_CONNECTABLE (remote));

  g_cond_signal (&quicsink->ctx_change);

  GST_TRACE_OBJECT (quicsink, "Connection with %s closed", addr);

  g_free (addr);
}

static void gst_quicsink_common_user_interface_init (gpointer g_iface,
    gpointer iface_data)
{
  GstQuicLibCommonUserInterface *iface = g_iface;

  iface->new_connection = quicsink_user_new_connection;
  iface->handshake_complete = quicsink_user_handshake_complete;
  iface->stream_opened = quicsink_user_stream_opened;
  iface->stream_closed = quicsink_user_stream_closed;
  iface->stream_data = NULL;
  iface->stream_ackd = quicsink_user_stream_ackd;
  iface->datagram_data = NULL;
  iface->datagram_ackd = quicsink_user_datagram_ackd;
  iface->connection_error = quicsink_user_connection_error;
  iface->connection_closed = quicsink_user_connection_closed;
}

/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
static gboolean
quicsink_init (GstPlugin * quicsink)
{
  /* debug category for filtering log messages
   *
   * exchange the string 'Template quicsink' with your description
   */
  GST_DEBUG_CATEGORY_INIT (gst_quicsink_debug, "quicsink",
      0, "Template quicsink");

  return GST_ELEMENT_REGISTER (quicsink, quicsink);
}

/* PACKAGE: this is usually set by meson depending on some _INIT macro
 * in meson.build and then written into and defined in config.h, but we can
 * just set it ourselves here in case someone doesn't use meson to
 * compile this code. GST_PLUGIN_DEFINE needs PACKAGE to be defined.
 */
#ifndef PACKAGE
#define PACKAGE "quicsink"
#endif

/* gstreamer looks for this structure to register quicsinks
 *
 * exchange the string 'Template quicsink' with your quicsink description
 */
GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    quicsink,
    "quicsink",
    quicsink_init,
    PACKAGE_VERSION, GST_LICENSE, GST_PACKAGE_NAME, GST_PACKAGE_ORIGIN)
