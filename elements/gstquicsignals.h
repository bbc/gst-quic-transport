/*
 * GStreamer
 * Copyright (C) 2023 Samuel Hurst <sam.hurst@bbc.co.uk>
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

#ifndef GST_PLUGIN_SRC_QUICLIB_GSTQUICSIGNALS_H_
#define GST_PLUGIN_SRC_QUICLIB_GSTQUICSIGNALS_H_

#include <gst/gst.h>
#include <gio/gio.h>

typedef enum {
  GST_QUICLIB_HANDSHAKE_COMPLETE_SIGNAL,
  GST_QUICLIB_STREAM_OPENED_SIGNAL,
  GST_QUICLIB_STREAM_CLOSED_SIGNAL,
  GST_QUICLIB_STREAM_FLOW_CONTROL_LIMITED_SIGNAL,
  GST_QUICLIB_CONN_FLOW_CONTROL_LIMITED_SIGNAL,
  GST_QUICLIB_CONN_ERROR_SIGNAL,
  GST_QUICLIB_CONN_CLOSED_SIGNAL,
  GST_QUICLIB_SIGNALS_MAX
} GstQuicLibConnSignals;

/*#define gst_quiclib_install_conn_signals(signal_src) \
  do { \
	signal_src->signals[GST_QUICLIB_HANDSHAKE_COMPLETE_SIGNAL] = \
      gst_quiclib_handshake_complete_signal_new (signal_src); \
	signal_src->signals[GST_QUICLIB_STREAM_OPENED_SIGNAL] = \
	  gst_quiclib_stream_opened_signal_new (signal_src); \
	signal_src->signals[GST_QUICLIB_STREAM_CLOSED_SIGNAL] = \
	  gst_quiclib_stream_closed_signal_new (signal_src); \
    signal_src->signals[GST_QUICLIB_STREAM_FLOW_CONTROL_LIMITED_SIGNAL] = \
      gst_quiclib_stream_flow_control_limited_signal_new (signal_src); \
    signal_src->signals[GST_QUICLIB_CONN_FLOW_CONTROL_LIMITED_SIGNAL] = \
      gst_quiclib_conn_flow_control_limited_signal_new (signal_src); \
    signal_src->signals[GST_QUICLIB_CONN_ERROR_SIGNAL] = \
      gst_quiclib_conn_error_signal_new (signal_src); \
    signal_src->signals[GST_QUICLIB_CONN_CLOSED_SIGNAL] = \
      gst_quiclib_conn_closed_signal_new (signal_src); \
  } while (0)*/

/*
 * Signal called when the QUIC handshake completes, and application data can be
 * exchanged between peers.
 */
#define GST_QUICLIB_HANDSHAKE_COMPLETE_SIGNAL_ID "quic-handshake-complete"

/*guint gst_quiclib_handshake_complete_signal_new (GstElement *signal_src);*/

#define gst_quiclib_handshake_complete_signal_new(signal_src_class) \
  g_signal_new (GST_QUICLIB_HANDSHAKE_COMPLETE_SIGNAL_ID, \
      G_TYPE_FROM_CLASS (signal_src_class), \
      G_SIGNAL_RUN_LAST, \
      0, NULL, NULL, NULL, \
      G_TYPE_NONE, 2, G_TYPE_SOCKET_ADDRESS, G_TYPE_STRING)

/*void gst_quiclib_handshake_complete_signal_emit (GstElement *signal_src,
    GSocketAddress *sa, const gchar *negotiated_alpn);*/

#define gst_quiclib_handshake_complete_signal_emit(signal_src, sa, alpn) \
  g_signal_emit_by_name (G_OBJECT (signal_src), \
      GST_QUICLIB_HANDSHAKE_COMPLETE_SIGNAL_ID, sa, alpn)

typedef void (*gst_quiclib_handshake_complete_signal_cb) (
    GstElement *signal_src, GSocketAddress *sa, const gchar *negotiated_alpn,
    gpointer user_data);

/*gulong gst_quiclib_handshake_complete_signal_connect (GstElement *signal_src,
    gst_quiclib_handshake_complete_signal_cb cb, gpointer user_data);*/

#define gst_quiclib_handshake_complete_signal_connect( \
    signal_src, cb, user_data) \
      g_signal_connect_data (signal_src, \
          GST_QUICLIB_HANDSHAKE_COMPLETE_SIGNAL_ID, (GCallback) cb, user_data, \
          NULL, 0)

#define gst_quiclib_handshake_complete_signal_disconnect( \
    signal_src, handler_id) \
      g_signal_handler_disconnect (signal_src, handler_id)

/*
 * Signal called when a new stream is opened.
 */
#define GST_QUICLIB_STREAM_OPENED_SIGNAL_ID "quic-stream-opened"
/*guint gst_quiclib_stream_opened_signal_new (GstElement *signal_src);*/
#define gst_quiclib_stream_opened_signal_new(signal_src_class) \
  g_signal_new (GST_QUICLIB_STREAM_OPENED_SIGNAL_ID, \
        G_TYPE_FROM_CLASS (signal_src_class), \
        G_SIGNAL_RUN_LAST, \
        0, NULL, NULL, NULL, \
        G_TYPE_NONE, 1, G_TYPE_UINT64)

/*void gst_quiclib_stream_opened_signal_emit (GstElement *signal_src,
    guint64 stream_id);*/
#define gst_quiclib_stream_opened_signal_emit(signal_src, stream_id) \
  g_signal_emit_by_name (G_OBJECT (signal_src), \
      GST_QUICLIB_STREAM_OPENED_SIGNAL_ID, stream_id)

typedef void (*gst_quiclib_stream_opened_signal_cb) (GstElement *signal_src,
    guint64 stream_id, gpointer user_data);

/*gulong gst_quiclib_stream_opened_signal_connect (GstElement *signal_src,
    gst_quiclib_stream_opened_signal_cb cb, gpointer user_data);*/
#define gst_quiclib_stream_opened_signal_connect(signal_src, cb, user_data) \
  g_signal_connect_data (signal_src, GST_QUICLIB_STREAM_OPENED_SIGNAL_ID, \
        (GCallback) cb, user_data, NULL, 0)

#define gst_quiclib_stream_opened_signal_disconnect(signal_src, handler_id) \
  g_signal_handler_disconnect (signal_src, handler_id)

/*
 * Signal called when a stream is closed.
 */
#define GST_QUICLIB_STREAM_CLOSED_SIGNAL_ID "quic-stream-closed"

#define gst_quiclib_stream_closed_signal_new(signal_src_class) \
  g_signal_new (GST_QUICLIB_STREAM_CLOSED_SIGNAL_ID, \
        G_TYPE_FROM_CLASS (signal_src_class), \
        G_SIGNAL_RUN_LAST, \
        0, NULL, NULL, NULL, \
        G_TYPE_NONE, 1, G_TYPE_UINT64);

#define gst_quiclib_stream_closed_signal_emit(signal_src, stream_id) \
  g_signal_emit_by_name (G_OBJECT (signal_src), \
      GST_QUICLIB_STREAM_CLOSED_SIGNAL_ID, stream_id)

typedef void (*gst_quiclib_stream_closed_signal_cb) (GstElement *signal_src,
    guint64 stream_id, gpointer user_data);

#define gst_quiclib_stream_closed_signal_connect(signal_src, cb, user_data) \
  g_signal_connect_data (signal_src, GST_QUICLIB_STREAM_CLOSED_SIGNAL_ID, \
          (GCallback) cb, user_data, NULL, 0)

#define gst_quiclib_stream_closed_signal_disconnect(signal_src, handler_id) \
  g_signal_handler_disconnect (signal_src, handler_id)

/*
 * Signal called when a stream hits it's flow control limits
 */
#define GST_QUICLIB_STREAM_FLOW_CONTROL_SIGNAL_ID "quic-stream-limited"

#define gst_quiclib_stream_flow_control_limited_signal_new(signal_src_class) \
  g_signal_new (GST_QUICLIB_STREAM_FLOW_CONTROL_SIGNAL_ID, \
        G_TYPE_FROM_CLASS (signal_src_class), \
        G_SIGNAL_RUN_LAST, \
        0, NULL, NULL, NULL, \
        G_TYPE_NONE, 2, G_TYPE_UINT64, G_TYPE_UINT64)

#define gst_quiclib_stream_flow_control_limited_signal_emit( \
    signal_src, stream_id, max_stream_data) \
      g_signal_emit_by_name (G_OBJECT (signal_src), \
          GST_QUICLIB_STREAM_FLOW_CONTROL_SIGNAL_ID, stream_id, \
          max_stream_data);

typedef void (*gst_quiclib_stream_flow_control_limited_signal_cb) (
    GstElement *signal_src, guint64 stream_id, guint64 max_stream_data,
    gpointer user_data);

#define gst_quiclib_stream_flow_control_limited_signal_connect( \
    signal_src, cb, user_data) \
        g_signal_connect_data (signal_src, \
            GST_QUICLIB_STREAM_FLOW_CONTROL_SIGNAL_ID, (GCallback) cb, \
            user_data, NULL, 0)

#define gst_quiclib_stream_flow_control_limited_signal_disconnect(signal_src, \
		handler_id) g_signal_handler_disconnect (signal_src, handler_id)

/*
 * Signal called when the QUIC connection hits flow control limits
 */
#define GST_QUICLIB_CONN_FLOW_CONTROL_SIGNAL_ID "quic-conn-limited"

#define gst_quiclib_conn_flow_control_limited_signal_new(signal_src_class) \
  g_signal_new (GST_QUICLIB_CONN_FLOW_CONTROL_SIGNAL_ID, \
      G_TYPE_FROM_CLASS (signal_src_class), \
      G_SIGNAL_RUN_LAST, \
      0, NULL, NULL, NULL, \
      G_TYPE_NONE, 1, G_TYPE_UINT64);

#define gst_quiclib_conn_flow_control_limited_signal_emit( \
    signal_src, bytes_in_flight) \
      g_signal_emit_by_name (G_OBJECT (signal_src), \
          GST_QUICLIB_CONN_FLOW_CONTROL_SIGNAL_ID, bytes_in_flight)

typedef void (*gst_quiclib_conn_flow_control_limited_signal_cb) (
    GstElement *signal_src, guint64 bytes_in_flight, gpointer user_data);

#define gst_quiclib_conn_flow_control_limited_signal_connect( \
    signal_src, cb, user_data) \
	  g_signal_connect_data (signal_src, \
	      GST_QUICLIB_CONN_FLOW_CONTROL_SIGNAL_ID, (GCallback) cb, user_data, \
		  NULL, 0)

#define gst_quiclib_conn_flow_control_limited_signal_disconnect(signal_src, \
    handler_id) g_signal_handler_disconnect (signal_src, handler_id)

/*
 * Signal called when the connection encounters an error
 */
#define GST_QUICLIB_CONN_ERROR_SIGNAL_ID "quic-conn-error"

#define gst_quiclib_conn_error_signal_new(signal_src_class) \
  g_signal_new (GST_QUICLIB_CONN_ERROR_SIGNAL_ID, \
      G_TYPE_FROM_CLASS (signal_src_class), \
      G_SIGNAL_RUN_LAST, \
      0, NULL, NULL, NULL, \
      G_TYPE_NONE, 1, G_TYPE_UINT64);

#define gst_quiclib_conn_error_signal_emit(signal_src, error) \
  g_signal_emit_by_name (G_OBJECT (signal_src), \
      GST_QUICLIB_CONN_ERROR_SIGNAL_ID, error)

typedef void (*gst_quiclib_conn_error_signal_cb) (GstElement *signal_src,
    guint64 error, gpointer user_data);

#define gst_quiclib_conn_error_signal_connect(signal_src, cb, user_data) \
  g_signal_connect_data (signal_src, GST_QUICLIB_CONN_ERROR_SIGNAL_ID, \
      (GCallback) cb, user_data, NULL, 0)

#define gst_quiclib_error_signal_disconnect(signal_src, handler_id) \
  g_signal_handler_disconnect (signal_src, handler_id)

/*
 * Signal called when the connection with a peer is complete and can no longer
 * be used for exchanging application data with the noted peer.
 */
#define GST_QUICLIB_CONN_CLOSED_SIGNAL_ID "quic-conn-closed"

#define gst_quiclib_conn_closed_signal_new(signal_src_class) \
  g_signal_new (GST_QUICLIB_CONN_CLOSED_SIGNAL_ID, \
      G_TYPE_FROM_CLASS (signal_src_class), \
      G_SIGNAL_RUN_LAST, \
      0, NULL, NULL, NULL, \
      G_TYPE_NONE, 1, G_TYPE_SOCKET_ADDRESS)

#define gst_quiclib_conn_closed_signal_emit(signal_src, sa) \
  g_signal_emit_by_name (G_OBJECT (signal_src), \
      GST_QUICLIB_CONN_CLOSED_SIGNAL_ID, sa)

typedef void (*gst_quiclib_conn_closed_signal_cb) (GstElement *signal_src,
    GSocketAddress *sa, gpointer user_data);

#define gst_quiclib_conn_closed_signal_connect(signal_src, cb, user_data) \
  g_signal_connect_data (signal_src, GST_QUICLIB_CONN_CLOSED_SIGNAL_ID, \
      (GCallback) cb, user_data, NULL, 0)

#define gst_quiclib_conn_closed_signal_disconnect(signal_src, handler_id) \
  g_signal_handler_disconnect (signal_src, handler_id)


#endif /* GST_PLUGIN_SRC_QUICLIB_GSTQUICSIGNALS_H_ */
