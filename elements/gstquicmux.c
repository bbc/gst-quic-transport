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
 * SECTION:gstquicmux
 * @title: GstQuicMux
 * @short description: Multiplex data to be sent on a QUIC transport connection
 *
 * The quicmux element is used to multiplex QUIC stream data and QUIC datagram
 * frames to be sent on a QUIC transport connection. It is designed to be used
 * with a quicsink element in the downstream direction. The quicmux element
 * takes care of adding the GstQuicLibStreamMeta and GstQuicLibDatagramMeta meta
 *  objects to buffers, so that they get sent on the right channels upon
 *  arriving at the QUIC transport layer.
 *
 * New streams are opened by requesting a new sink pad of the appropriate type.
 * The quicmux element queries the associated quicsink element for a new stream,
 * and if a new stream can be opened then the new pad will be linked. Buffers
 * received on stream pads do not map directly to STREAM frames at the QUIC
 * layer. Instead, the GstBuffer objects received in the chain function are just
 * arbitrary stream data objects which will be payloaded by the QUIC transport
 * library. One input buffer may map to one or more STREAM frames. Therefore,
 * upstream elements should not perform any chunking of stream data objects as
 * this results in more buffer overheads.
 *
 * Conversely, GstBuffer objects received in the chain function from a datagram
 * sink pad will map directly to a QUIC DATAGRAM  frame, and as such upstream
 * elements should perform chunking of data to fit within the QUIC DATAGRAM
 * frame maximum transmission unit.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gst/gst.h>

#include "gstquicmux.h"
#include "gstquicsink.h"
#include "gstquicstream.h"
#include "gstquicdatagram.h"

GST_DEBUG_CATEGORY_STATIC (gst_quic_mux_debug);
#define GST_CAT_DEFAULT gst_quic_mux_debug

G_DEFINE_TYPE (GstQuicMuxStreamObject, gst_quic_mux_stream_object,
    GST_TYPE_OBJECT);

static void
gst_quic_mux_stream_object_class_init (GstQuicMuxStreamObjectClass *klass)
{
}

static void
gst_quic_mux_stream_object_init (GstQuicMuxStreamObject *stream)
{
  stream->sinkpad = NULL;
  stream->stream_id = -1;
  stream->offset = 0;

  g_mutex_init (&stream->mutex);
  g_cond_init (&stream->wait);
}

GstQuicMuxStreamObject *
quic_mux_new_stream_object (GstQuicMux *quicmux, guint64 stream_id, GstPad *pad)
{
  GstQuicMuxStreamObject *stream =
      g_object_new (GST_TYPE_QUICMUX_STREAM_OBJECT, NULL);
  if (stream == NULL) return NULL;

  stream->stream_id = stream_id;
  stream->sinkpad = pad;
  g_mutex_lock (&quicmux->mutex);
  g_hash_table_insert (quicmux->pad_to_stream, pad, stream);
  g_object_ref (stream);
  g_hash_table_insert (quicmux->id_to_stream, &stream->stream_id, stream);
  g_mutex_unlock (&quicmux->mutex);

  GST_TRACE_OBJECT (quicmux, "Added new stream object with stream ID %lu and "
      "pad %p - pad_to_stream count %u, id_to_stream count %u",
      stream->stream_id, stream->sinkpad,
      g_hash_table_size (quicmux->pad_to_stream),
      g_hash_table_size (quicmux->id_to_stream));

  return stream;
}

enum
{
  PROP_0,
};

/* the capabilities of the inputs and outputs.
 *
 * describe the real formats here.
 */
static GstStaticPadTemplate sink_bidi_factory = GST_STATIC_PAD_TEMPLATE (
    "sink_bidi_local_%u", GST_PAD_SINK, GST_PAD_REQUEST,
    GST_STATIC_CAPS (QUICLIB_BIDI_STREAM_CAP));

static GstStaticPadTemplate sink_uni_factory = GST_STATIC_PAD_TEMPLATE (
    "sink_uni_local_%u", GST_PAD_SINK, GST_PAD_REQUEST,
    GST_STATIC_CAPS (QUICLIB_UNI_STREAM_CAP));

static GstStaticPadTemplate sink_datagram_factory = GST_STATIC_PAD_TEMPLATE (
    "datagram_%u", GST_PAD_SINK, GST_PAD_REQUEST,
    GST_STATIC_CAPS (QUICLIB_DATAGRAM_CAP));

static GstStaticPadTemplate src_factory = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC, GST_PAD_ALWAYS, GST_STATIC_CAPS (QUICLIB_RAW));

#define gst_quic_mux_parent_class parent_class
G_DEFINE_TYPE (GstQuicMux, gst_quic_mux, GST_TYPE_ELEMENT);

GST_ELEMENT_REGISTER_DEFINE (quic_mux, "quicmux", GST_RANK_NONE,
    GST_TYPE_QUICMUX);

static void gst_quic_mux_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec);
static void gst_quic_mux_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec);

static gboolean gst_quic_mux_sink_event (GstPad * pad,
    GstObject * parent, GstEvent * event);
static gboolean gst_quic_mux_src_event (GstPad * pad,
    GstObject * parent, GstEvent * event);
static GstFlowReturn gst_quic_mux_chain (GstPad * pad,
    GstObject * parent, GstBuffer * buf);

static gboolean gst_quic_mux_element_events (GstElement *element,
    GstEvent *event);
static gboolean gst_quic_mux_sink_query (GstPad *pad, GstObject *parent,
    GstQuery *query);
static gboolean gst_quic_mux_src_query (GstPad *pad, GstObject *parent,
    GstQuery *query);

static GstPad * gst_quic_mux_request_new_pad (GstElement *element,
    GstPadTemplate *templ, const gchar *name, const GstCaps *caps);

static void gst_quic_mux_release_pad (GstElement *element, GstPad *pad);

GstPadLinkReturn gst_quic_mux_src_pad_linked (GstPad * pad, GstObject * parent,
    GstPad * peer);

/*
 * Local convenience functions
 */
gboolean gst_quic_mux_request_stashed_streams (GstQuicMux *quicmux);
gboolean gst_quic_mux_close_all_streams (GstQuicMux *quicmux);

/* GObject vmethod implementations */

/* initialize the quicmux's class */
static void
gst_quic_mux_class_init (GstQuicMuxClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class;

  gobject_class = (GObjectClass *) klass;
  gstelement_class = (GstElementClass *) klass;

  gstelement_class->request_new_pad = gst_quic_mux_request_new_pad;
  gstelement_class->release_pad = gst_quic_mux_release_pad;
  gstelement_class->send_event = gst_quic_mux_element_events;

  gobject_class->set_property = gst_quic_mux_set_property;
  gobject_class->get_property = gst_quic_mux_get_property;

  gst_element_class_set_static_metadata (gstelement_class,
      "QUIC Transport Multiplexer",
      "Muxer/Network",
      "Work in tandem with a quicsink element to multiplex data flows onto QUIC"
      " transport streams and datagrams",
      "Sam Hurst <sam.hurst@bbc.co.uk>");

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&src_factory));
  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&sink_bidi_factory));
  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&sink_uni_factory));
  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&sink_datagram_factory));
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad callback functions
 * initialize instance structure
 */
static void
gst_quic_mux_init (GstQuicMux * quicmux)
{
  quicmux->srcpad = gst_pad_new_from_static_template (&src_factory, "src");
  gst_pad_use_fixed_caps (quicmux->srcpad);
  gst_element_add_pad (GST_ELEMENT (quicmux), quicmux->srcpad);
  gst_pad_set_event_function (quicmux->srcpad,
      GST_DEBUG_FUNCPTR (gst_quic_mux_src_event));
  gst_pad_set_link_function (quicmux->srcpad,
      GST_DEBUG_FUNCPTR (gst_quic_mux_src_pad_linked));
  gst_pad_set_query_function (quicmux->srcpad,
      GST_DEBUG_FUNCPTR (gst_quic_mux_src_query));

  quicmux->pad_to_stream = g_hash_table_new_full (g_direct_hash, g_direct_equal,
      NULL, gst_object_unref);
  quicmux->id_to_stream = g_hash_table_new_full (g_int64_hash, g_int64_equal,
      NULL, gst_object_unref);

  g_mutex_init (&quicmux->mutex);
}

static void
gst_quic_mux_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  /*GstQuicMux *quicmux = GST_QUICMUX (object);*/

  switch (prop_id) {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_quic_mux_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  /*GstQuicMux *quicmux = GST_QUICMUX (object);*/

  switch (prop_id) {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

/* GstElement vmethod implementations */

struct QuicMuxStreamRequestPair {
  GstQuicMuxStreamObject *stream;
  GstQuery *query;
};

/*
 * Lookup the stream object that is related to a given sink pad, used to map
 * a data flow to a stream ID (or datagram flow).
 */
gboolean
quic_mux_search_stream_objects (GList *list, GstPad *pad,
    GstQuicMuxStreamObject **object)
{
  GList *it = g_list_first (list);

  while (it != NULL) {
    GstQuicMuxStreamObject *obj = (GstQuicMuxStreamObject *) it->data;
    if (obj->sinkpad == pad) {
      *object = obj;
      return TRUE;
    }

    it = g_list_next (it);
  }

  return FALSE;
}

/*
 * Iterate through each of the BIDI, UNI stream and datagram sink pads for a
 * match to map a data flow to a stream ID (or datagram flow).
 */
GstQuicMuxStreamObject *
quic_mux_get_stream_from_pad (GstQuicMux *quicmux, GstPad *pad)
{
  GstQuicMuxStreamObject *rv = NULL;

  g_mutex_lock (&quicmux->mutex);

  rv = g_hash_table_lookup (quicmux->pad_to_stream, (gconstpointer) pad);

  g_mutex_unlock (&quicmux->mutex);

  return rv;
}

/**
 * Used when a sink pad is unlinked, which indicates that the stream associated
 * with it should be closed.
 *
 * @param list The list of streams to search within for @p pad.
 * @param pad The sink pad that is being unlinked
 * @param reason The reason for the stream closing, usually 0 to indicate a
 *               graceful shutdown.
 * @return TRUE if the pad was found in @p list, otherwise FALSE.
 */
gboolean
quic_mux_close_stream_from_pad (GstQuicMux *quicmux, GstPad *pad,
    guint64 reason)
{
  GstQuicMuxStreamObject *stream;
  guint64 stream_id = G_MAXUINT64;

  g_mutex_lock (&quicmux->mutex);

  if (g_hash_table_lookup_extended (quicmux->pad_to_stream, pad, NULL,
      (gpointer *) &stream))
  {
    stream_id = stream->stream_id;
    g_hash_table_remove (quicmux->pad_to_stream, pad);
    g_hash_table_remove (quicmux->id_to_stream, &stream_id);
  }

  g_mutex_unlock (&quicmux->mutex);

  if (stream_id < QUICLIB_VARINT_MAX) {
    GstQuery *closeq = gst_query_cancel_quiclib_stream (stream_id, reason);
    if (!gst_pad_peer_query (quicmux->srcpad, closeq)) {
      GST_ERROR_OBJECT (quicmux, "Close stream query failed!");
    }
    gst_query_unref (closeq);

    return TRUE;
  }

  return FALSE;
}

void
quic_mux_pad_linked (GstPad * self, GstPad * peer, gpointer user_data)
{
  GstQuicMux *quicmux = GST_QUICMUX (gst_pad_get_parent (self));

  GST_DEBUG_OBJECT (quicmux, "Pad %p linked to peer %p", self, peer);
}

void
quic_mux_pad_unlinked (GstPad * self, GstPad * peer, gpointer user_data)
{
  GstQuicMux *quicmux = GST_QUICMUX (gst_pad_get_parent (self));

  GST_DEBUG_OBJECT (quicmux, "Pad %p unlinked from peer %p", self, peer);

  quic_mux_close_stream_from_pad (quicmux, self, 0);

  gst_element_remove_pad (GST_ELEMENT (quicmux), self);
}

/**
 * Implements GstElement::request_new_pad
 *
 * Called when a new sink pad is requested. Uses the media type in the caps to
 * open a bidi or uni stream via a query to quicsink, if required.
 */
static GstPad *
gst_quic_mux_request_new_pad (GstElement *element, GstPadTemplate *templ,
    const gchar *n, const GstCaps *caps)
{
  enum {
    PAD_NONE,
    PAD_BIDI,
    PAD_UNI,
    PAD_DATAGRAM
  } pad_type = PAD_NONE;
  GstQuicMux *quicmux = GST_QUICMUX (element);
  GstCaps *templ_caps = gst_pad_template_get_caps (templ);
  GstQuery *new_stream_query = NULL;
  GstPad *pad;
  guint64 stream_id = G_MAXUINT64;

  const gchar *media_type =
      gst_structure_get_name (gst_caps_get_structure (templ_caps, 0));

  GST_DEBUG_OBJECT (quicmux, "New pad %s requested (%s) with caps %" GST_PTR_FORMAT,
      media_type, n, caps);

  g_mutex_lock (&quicmux->mutex);

  /* application/quic+[s|d]... */
  switch (media_type[17]) {
  case 's':
    /* application/quic+stream+[b|u]... */
    switch (media_type[24]) {
    case 'b':
    {
      /* BIDI stream requested */
      GstStructure *caps_structure;

      caps_structure = gst_caps_get_structure (caps, 0);
      if (caps_structure) {
        if (gst_structure_get_uint64 (caps_structure, QUICLIB_STREAMID_KEY,
            &stream_id) == TRUE) {
          GstQuery *q;

          GST_DEBUG_OBJECT (quicmux,
              "Request for stream with specific stream ID %lu", stream_id);

          if (g_hash_table_lookup_extended (quicmux->id_to_stream, &stream_id,
              NULL, NULL)) {
            GST_WARNING_OBJECT (quicmux, "Already have a pad for stream %lu",
                stream_id);
            g_mutex_unlock (&quicmux->mutex);
            return NULL;
          }

          q = gst_query_quiclib_stream_state (stream_id);

          if (gst_pad_peer_query (quicmux->srcpad, q) == TRUE) {
            GstQuicLibStreamState state;

            gst_query_parse_quiclib_stream_state (q, &state);

            if (!(state & QUIC_STREAM_OPEN) ||
                (state & QUIC_STREAM_CLOSED_SENDING)) {
              GST_WARNING_OBJECT (quicmux,
                  "Stream %lu is not open for sending!", stream_id);
              g_mutex_unlock (&quicmux->mutex);
              return NULL;
            }
          }
        }
      }

      pad_type = PAD_BIDI;

      if (stream_id == G_MAXUINT64) {
        new_stream_query = gst_query_new_quiclib_stream (QUIC_STREAM_BIDI);
      }
      break;
    }
    case 'u':
      /* UNI stream requested */

      pad_type = PAD_UNI;

      new_stream_query = gst_query_new_quiclib_stream (QUIC_STREAM_UNI);

      break;
    default:
      goto error;
    }
    break;
  case 'd':
    /* Datagram pad - TODO check whether datagrams are negotiated, then go */
    pad_type = PAD_DATAGRAM;
    break;
  default:
    goto error;
  }

  g_mutex_unlock (&quicmux->mutex);

  gst_caps_unref (templ_caps);

  if (pad_type == PAD_NONE) {
    GST_WARNING_OBJECT (quicmux, "Couldn't open new stream, rejecting pad");
    g_mutex_unlock (&quicmux->mutex);
    return NULL;
  }

  pad = gst_pad_new_from_template (templ, NULL);

  switch (pad_type) {
    case PAD_BIDI:
    case PAD_UNI:
      gst_pad_set_chain_function (pad, gst_quic_mux_stream_chain);
      break;
    case PAD_DATAGRAM:
      gst_pad_set_chain_function (pad, gst_quic_mux_dgram_chain);
      break;
    default:
      g_assert (0);
  }
  gst_pad_set_event_function (pad, gst_quic_mux_sink_event);
  gst_pad_set_query_function (pad, gst_quic_mux_sink_query);
  g_signal_connect (pad, "linked", (GCallback) quic_mux_pad_linked, NULL);
  g_signal_connect (pad, "unlinked", (GCallback) quic_mux_pad_unlinked, NULL);

  /*
   * If stream_id is set to an actual stream ID, then we should be opening the
   * sending end of an extant bidi stream (and as such, no new stream query is
   * needed).
   */
  g_assert ((stream_id == G_MAXUINT64 && new_stream_query) ||
      (stream_id != G_MAXUINT64 && new_stream_query == NULL));

  /*
   * Send the new stream query
   */
  if (new_stream_query && gst_pad_is_linked (quicmux->srcpad)) {
    gboolean rv;
    rv = gst_pad_peer_query (quicmux->srcpad, new_stream_query);

    if (rv == TRUE) {
      GstQuicLibStreamState status;
      guint64 new_stream_id;
      gst_query_parse_new_quiclib_stream (new_stream_query, &new_stream_id,
          &status);

      if (gst_quiclib_stream_state_is_okay (status)) {
        GST_INFO_OBJECT (quicmux, "Stream ID %ld for stream request \"%s\"",
                  new_stream_id, gst_pad_get_name (quicmux->srcpad));
        gst_query_unref (new_stream_query);
        new_stream_query = NULL;

        if (stream_id != G_MAXUINT64 && stream_id != new_stream_id) {
          GST_WARNING_OBJECT (quicmux, "Couldn't get pad for requested stream "
              "ID %lu", stream_id);
        } else {
          stream_id = new_stream_id;
        }

      } else {
        gchar *statestr;

        statestr = g_enum_to_string (quiclib_stream_status_get_type(), status);

        GST_WARNING_OBJECT (quicmux, "Couldn't open new stream: %s", statestr);
        stream_id = G_MAXUINT64;

        g_free (statestr);
      }
    } else {
      GST_ERROR_OBJECT (quicmux, "Couldn't send new stream query!");
      gst_object_unref (pad);
      g_mutex_unlock (&quicmux->mutex);
      return NULL;
    }
  }

  /*
   * If the stream opened correctly, then the query object will be NULL. If not,
   * we should stash it for later when the QUIC transport connection is able to
   * open it, as the connection could still be in the INITIAL phase.
   *
   * TODO: We could be sitting against the MAX_STREAMS limit, and awaiting more
   * flow control credit from the remote endpoint. How should this be managed..?
   */
  if (new_stream_query) {
    struct QuicMuxStreamRequestPair *pair =
        g_malloc (sizeof (struct QuicMuxStreamRequestPair));

    g_return_val_if_fail (pair, NULL);

    GST_INFO_OBJECT (quicmux,
        "Stashing new stream request query for %s until connection ready",
        gst_pad_get_name (pad));

    pair->query = new_stream_query;
    pair->stream = quic_mux_new_stream_object (quicmux, G_MAXUINT64, pad);

    quicmux->stream_open_requests =
        g_list_append (quicmux->stream_open_requests, pair);
  } else {
    quic_mux_new_stream_object (quicmux, stream_id, pad);
  }

  gst_element_add_pad (GST_ELEMENT (quicmux), pad);


  return pad;

error:
{
  gchar *str = gst_caps_to_string (caps);
  GST_WARNING_OBJECT (quicmux, "Unknown or incompatible caps: %s", str);
  g_free (str);
  return NULL;
}
}

/**
 * Implements GstElement::release_pad
 */
static void
gst_quic_mux_release_pad (GstElement *element, GstPad *pad)
{
  GstQuicMux *quicmux = GST_QUICMUX (element);

  quic_mux_close_stream_from_pad (quicmux, pad, 0);

  GST_DEBUG_OBJECT (quicmux, "Removing pad %s", gst_pad_get_name (pad));
  gst_element_remove_pad (element, pad);
}

/**
 * Implements GstPadEventFunction for sink pads
 */
static gboolean
gst_quic_mux_sink_event (GstPad * pad, GstObject * parent,
    GstEvent * event)
{
  GstQuicMux *quicmux;
  gboolean ret = TRUE;

  quicmux = GST_QUICMUX (parent);

  GST_LOG_OBJECT (quicmux, "Received %s sink event: %" GST_PTR_FORMAT,
      GST_EVENT_TYPE_NAME (event), event);

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_CAPS:
    {
      GstCaps *caps;

      gst_event_parse_caps (event, &caps);
      /* TODO: do something with the caps? */

      /* and forward */
      ret = gst_pad_event_default (pad, parent, event);
      break;
    }
    case GST_EVENT_SEGMENT:
    {
      ret = gst_pad_push_event (quicmux->srcpad, event);
      break;
    }
    default:
      ret = gst_pad_event_default (pad, parent, event);
      break;
  }

  return ret;
}

/**
 * Implements GstPadEventFunction for the src pad between us and quicsink.
 */
static gboolean
gst_quic_mux_src_event (GstPad * pad, GstObject * parent, GstEvent * event)
{
  GstQuicMux *quicmux = GST_QUICMUX (parent);
  const GstStructure *s;
  gboolean ret;

  GST_LOG_OBJECT (quicmux, "Received %s src event: %" GST_PTR_FORMAT,
      GST_EVENT_TYPE_NAME (event), event);

  switch (GST_EVENT_TYPE (event)) {
  case GST_EVENT_CUSTOM_UPSTREAM:
    s = gst_event_get_structure (event);
    if (gst_structure_has_name (s, QUICLIB_CLIENT_CONNECT)) {
      /*
       * TODO: This is never called anyway.
       */
#if 0
      gst_structure_get_enum (s, GST_QUIC_QUERY_CONNECTION_STATE_TYPE_NAME,
            gst_quiclib_transport_state_get_type(), (gint *) &state);

      if (state < QUIC_STATE_HANDSHAKE) {
        GST_ERROR_OBJECT (quicmux, "Connection isn't open!");
      } else {
        gst_quic_mux_request_stashed_streams (quicmux);
      }
#else
      g_abort ();
#endif
    } else if (gst_structure_has_name (s, QUICLIB_HANDSHAKE_COMPLETE)) {
      ret = gst_quic_mux_request_stashed_streams (quicmux);
      break;
    } else if (gst_structure_has_name (s, QUICLIB_CONNECTION_CLOSE)) {
      gst_quic_mux_close_all_streams (quicmux);
      break;
    } else if (gst_structure_has_name (s, QUICLIB_STREAM_OPEN)) {
      /*
       * Do nothing for now
       */
      return TRUE;
    } else if (gst_structure_has_name (s, QUICLIB_STREAM_CLOSE)) {
      guint64 stream_id;
      GstQuicMuxStreamObject *stream;
      /*
       * Stream has been closed, clean up any state.
       */
      gst_quiclib_parse_stream_closed_event (event, &stream_id);

      g_mutex_lock (&quicmux->mutex);

      if (g_hash_table_lookup_extended (quicmux->id_to_stream, &stream_id, NULL,
          (gpointer *) &stream)) {
        GstPad *pad = stream->sinkpad;
        g_hash_table_remove (quicmux->pad_to_stream, pad);
        g_hash_table_remove (quicmux->id_to_stream, &stream_id);
      } else {
        GST_TRACE_OBJECT (quicmux, "Stream close for unknown stream ID %lu - "
            "might've already been closed", stream_id);
      }

      g_mutex_unlock (&quicmux->mutex);

      return TRUE;
    } else {
      GST_WARNING_OBJECT (quicmux,
          "Received unknown upstream event with name %s",
          gst_structure_get_name (s));
    }
    /* no break */
  default:
    ret = gst_pad_event_default (pad, parent, event);
    break;
  }

  return ret;
}

/*
 * A positive return value indicates the stream can send. A zero return value
 * indicates that the stream cannot send. A negative return value is an error.
 *
 * TODO: Read the flow credit and return the available flow control window
 * for this stream?
 */
gint
quic_mux_stream_can_send (GstQuicMux *quicmux, GstQuicMuxStreamObject *stream)
{
  GstQuery *q;
  GstQuicLibStreamState stream_state;

  q = gst_query_quiclib_stream_state (stream->stream_id);
  g_return_val_if_fail (gst_pad_query (gst_pad_get_peer (quicmux->srcpad), q),
      -1);
  gst_query_parse_quiclib_stream_state (q, &stream_state);
  if ((stream_state & QUIC_STREAM_DATA_BLOCKED) ||
      (stream_state & QUIC_STREAM_CONNECTION_BLOCKED) ||
      (stream_state & QUIC_STREAM_CLOSED_SENDING) ||
      stream_state >= QUIC_STREAM_ERROR_MAX_STREAMS) {
    return 0;
  }
  return 1;
}

/**
 * Implements GstPadChainFunction for the sink pads
 */
static gboolean print_pipeline = FALSE;

static GstFlowReturn
gst_quic_mux_stream_chain (GstPad * pad, GstObject * parent, GstBuffer * buf)
{
  GstQuicMux *quicmux;
  GstQuicMuxStreamObject *stream;
  GstQuicLibStreamMeta *smeta;
  gboolean rv;
  guint64 buflen = gst_buffer_get_size (buf);

  quicmux = GST_QUICMUX (parent);

  GST_QUICLIB_PRINT_BUFFER (quicmux, buf);

  stream = quic_mux_get_stream_from_pad (quicmux, pad);

  if (stream == NULL) {
    GST_WARNING_OBJECT (quicmux, "No stream associated with pad %"
        GST_PTR_FORMAT, pad);
    return GST_FLOW_QUIC_STREAM_CLOSED;
  } if (stream->stream_id == G_MAXUINT64) {
    GST_INFO_OBJECT (quicmux, "Received buffer of size %lu bytes from pad %p "
        "for as-yet unopened stream", gst_buffer_get_size (buf), pad);
  } else {
    GST_DEBUG_OBJECT (quicmux, "Received buffer of size %lu bytes from pad %p "
        "for stream %ld", gst_buffer_get_size (buf), pad, stream->stream_id);
  }

  g_mutex_lock (&stream->mutex);
  while (stream->stream_id == G_MAXUINT64) {
    /* Block and wait for the stream to become active downstream. */
    g_cond_wait (&stream->wait, &stream->mutex);
  }

  g_mutex_unlock (&stream->mutex);

  if (can_send < 0) {
    return GST_FLOW_ERROR;
  }

  /*
   * TODO: Is it to be expected for QUIC stream metas to already be on buffers?
   * Or should this element be the arbiter of the stream IDs?
   */
  smeta = gst_buffer_get_quiclib_stream_meta (buf);

  if (smeta != NULL) {
    if (smeta->stream_id != stream->stream_id) {
      GST_ERROR_OBJECT (quicmux, "Stream ID mismatch on received meta: %lu "
          "expected, meta contained %lu", stream->stream_id, smeta->stream_id);
      return GST_FLOW_ERROR;
    }
  } else {
    gst_buffer_add_quiclib_stream_meta (buf, stream->stream_id,
        stream->offset + 1, buflen,
        gst_buffer_has_flags (buf, GST_BUFFER_FLAG_LAST));
  }

  stream->offset += buflen;  

  if (print_pipeline == FALSE) {
    GstBin *pipeline = GST_BIN (gst_element_get_parent (quicmux));

    print_pipeline = TRUE;

    while (!GST_IS_PIPELINE (pipeline)) {
      GST_TRACE_OBJECT (quicmux, "Bin %s (%p) is not pipeline, going up...",
          gst_element_get_name (pipeline), pipeline);
      pipeline = GST_BIN (gst_element_get_parent (pipeline));
    }

    GST_TRACE_OBJECT (quicmux, "Found pipeline %s (%p)",
        gst_element_get_name (pipeline), pipeline);

    gst_debug_bin_to_dot_file_with_ts (pipeline, GST_DEBUG_GRAPH_SHOW_ALL,
        "quicmux-chain"/*-unlinked-error"*/);
  }

  gst_object_ref (G_OBJECT (pad));

  rv = gst_pad_push (quicmux->srcpad, buf);
  GST_TRACE_OBJECT (quicmux, "Returning %d for buffer on stream %lu", rv,
      stream->stream_id);
  /*
   * Check for if pad is linked, in case the stream has been closed and the sink 
   * pad removed.
   */
  if (rv == GST_FLOW_QUIC_STREAM_CLOSED && gst_pad_is_linked (pad)) {
    gst_element_remove_pad (GST_ELEMENT (quicmux), pad);
  }

  gst_object_unref (G_OBJECT (pad));
  return rv;
}

static GstFlowReturn
gst_quic_mux_dgram_chain (GstPad * pad, GstObject * parent, GstBuffer * buf)
{
  GstQuicMux *quicmux = GST_QUICMUX (parent);
  GstQuicLibDatagramMeta *dmeta;

  dmeta = gst_buffer_get_quiclib_datagram_meta (buf);
  if (!dmeta) {
    gst_buffer_add_quiclib_datagram_meta (buf, gst_buffer_get_size (buf));
  }

  return gst_pad_push (quicmux->srcpad, buf);
}

/**
 * Implements GstPadLinkFunction for the src pad, and is used to kick off the
 * starting of stashed streams if the transport connection is in an appropriate
 * state to support streams.
 */
GstPadLinkReturn
gst_quic_mux_src_pad_linked (GstPad * pad, GstObject * parent, GstPad * peer)
{
  GstQuicMux *quicmux = GST_QUICMUX (parent);
  GstQuery *q;
  GstQuicLibTransportState state;

  q = gst_query_new_quiclib_conn_state ();

  g_return_val_if_fail (gst_pad_query (peer, q), GST_PAD_LINK_REFUSED);

  gst_query_parse_quiclib_conn_state (q, NULL, &state, NULL, NULL);
  if (state < QUIC_STATE_HANDSHAKE) {
    gchar *statestr;

    statestr = g_enum_to_string (gst_quiclib_transport_state_get_type(),
        state);

    GST_DEBUG_OBJECT (quicmux,
        "Src pad linked, but connection isn't ready to open streams: %s",
        statestr);

    g_free (statestr);

    return GST_PAD_LINK_OK;
  }

  GST_DEBUG_OBJECT (quicmux, "Src pad linked, %u stashed streams to open",
      g_list_length (quicmux->stream_open_requests));

  gst_quic_mux_request_stashed_streams (quicmux);

  return GST_PAD_LINK_OK;
}

/**
 * Open preliminary streams that are currently waiting for an active transport
 * connection.
 *
 * @return TRUE if all waiting streams could be opened, FALSE if any stream
 *         could not be opened. Note, that in this state you CANNOT assume that
 *         all other streams have been opened.
 */
gboolean
gst_quic_mux_request_stashed_streams (GstQuicMux *quicmux)
{
  while (quicmux->stream_open_requests != NULL) {
    struct QuicMuxStreamRequestPair *pair;
    gboolean rv;

    pair = (struct QuicMuxStreamRequestPair *)
        quicmux->stream_open_requests->data;

    rv = gst_pad_peer_query (quicmux->srcpad, pair->query);

    if (rv == TRUE) {
      GstQuicLibStreamState status;
      guint64 stream_id;

      gst_query_parse_new_quiclib_stream (pair->query,
          &stream_id, &status);

      if (!gst_quiclib_stream_state_is_okay (status)) {
        gchar *statestr;

        statestr = g_enum_to_string (quiclib_stream_status_get_type(), status);

        GST_WARNING_OBJECT (quicmux, "Couldn't open new stream: %s", statestr);

        g_free (statestr);

        gst_element_remove_pad (GST_ELEMENT (quicmux), pair->stream->sinkpad);
        gst_object_unref (pair->stream->sinkpad);
        gst_object_unref (pair->stream);
        g_free (pair);

        return FALSE;
      } else {
        GST_INFO_OBJECT (quicmux, "Stream ID %ld for stream request \"%s\"",
            stream_id, gst_pad_get_name (pair->stream->sinkpad));
        g_cond_signal (&pair->stream->wait);
      }
    } else {
      GST_ERROR_OBJECT (quicmux, "Couldn't send new stream query!");

      gst_element_remove_pad (GST_ELEMENT (quicmux), pair->stream->sinkpad);
      gst_object_unref (pair->stream->sinkpad);
      g_free (pair->stream);
    }

    g_free (pair);

    /* Pop the front object off */
    quicmux->stream_open_requests = g_list_delete_link (
        quicmux->stream_open_requests, quicmux->stream_open_requests);
  }

  return TRUE;
}

gboolean gst_quic_mux_close_all_streams (GstQuicMux *quicmux)
{
  /* TODO */
  g_assert (0);

  return FALSE;
}

/**
 * Implements GstElement::send_event
 *
 * Currently only forwards EOS events downstream
 */
static gboolean
gst_quic_mux_element_events (GstElement *element, GstEvent *event)
{
  GstQuicMux *mux;

  mux = GST_QUICMUX (element);

  GST_LOG_OBJECT (mux, "Received %s event: %" GST_PTR_FORMAT,
      GST_EVENT_TYPE_NAME (event), event);

  switch (GST_EVENT_TYPE (event)) {
  case GST_EVENT_EOS:
  {
    return gst_pad_push_event (mux->srcpad, event);
  }
  default:
    break;
  }

  return FALSE;
}

/**
 * Implements GstPadQueryFunction
 */
static gboolean
gst_quic_mux_sink_query (GstPad *pad, GstObject *parent, GstQuery *query)
{
  GstQuicMux *mux = GST_QUICMUX (parent);
  gboolean rv = FALSE;

  GST_DEBUG_OBJECT (mux, "Received %s query", GST_QUERY_TYPE_NAME (query));

  switch (GST_QUERY_TYPE (query)) {
    case GST_QUERY_CUSTOM:
      if (gst_query_is_associated_stream_id (query)) {
        GstPad *local_pad;
        GstQuicMuxStreamObject *stream;

        local_pad = gst_query_get_associated_stream_id_pad (query,
            GST_ELEMENT (mux));

        if (local_pad == NULL) {
          return FALSE;
        }

        stream = quic_mux_get_stream_from_pad (mux, local_pad);

        gst_object_unref (local_pad);

        if (stream->stream_id != G_MAXUINT64) {
          return gst_query_fill_get_associated_stream_id (query,
              stream->stream_id);
        }
      } else if (gst_query_is_associated_pad (query)) {
        guint64 stream_id;
        GstQuicMuxStreamObject *stream;
        gboolean rv = FALSE;

        stream_id = gst_query_get_associated_pad_stream_id (query);

        g_mutex_lock (&mux->mutex);

        if (g_hash_table_lookup_extended (mux->id_to_stream, &stream_id, NULL,
            (gpointer *) &stream)) {
          rv = gst_query_fill_get_associated_pad (query, stream->sinkpad);
        }

        g_mutex_unlock (&mux->mutex);

        return rv;
      }
      break;
    default:
      rv = gst_pad_query_default (pad, parent, query);
  }

  return rv;
}

static gboolean
gst_quic_mux_src_query (GstPad *pad, GstObject *parent, GstQuery *query)
{
  GstQuicMux *mux = GST_QUICMUX (parent);
  const gchar *query_type = GST_QUERY_TYPE_NAME (query);
  GstStructure *s;
  gboolean rv;

  GST_LOG_OBJECT (mux, "Received %s query", query_type);

  switch (GST_QUERY_TYPE (query)) {
  case GST_QUERY_CUSTOM:
    g_return_val_if_fail (gst_query_is_writable (query), FALSE);

    s = gst_query_writable_structure (query);

    g_return_val_if_fail (s, FALSE);

    if (gst_structure_has_name (s, QUICLIB_CLIENT_CONNECT)) {
      /* TODO: Check if the ALPN and host is acceptable? */

      GST_DEBUG_OBJECT (mux, "Sink has connected, %u streams waiting",
          g_list_length (mux->stream_open_requests));

      return gst_quic_mux_request_stashed_streams (mux);
    } else if (gst_structure_has_name (s, QUICLIB_HANDSHAKE_COMPLETE)) {
      GST_DEBUG_OBJECT (mux, "Handshake complete");
    } else if (gst_structure_has_name (s, QUICLIB_STREAM_OPEN)) {
      /* TODO: Request a new pad */
      /*g_assert (0);*/
    }
    break;
  case GST_QUERY_CAPS:
  {
    GstCaps *query_caps, *template_caps, *target_caps;
    GstStructure *capsstruct;
    GstQuicMuxStreamObject *stream;


    gst_query_parse_caps (query, &query_caps);
    template_caps = gst_pad_template_get_caps (
        gst_element_get_pad_template (GST_ELEMENT (parent), "src"));

    /*g_return_val_if_fail (query_caps != NULL && sink_caps != NULL, FALSE);*/
    if (query_caps) {
      target_caps = gst_caps_intersect (query_caps, template_caps);
    } else {
      target_caps = gst_caps_copy (template_caps);
    }

    g_assert (gst_caps_is_writable (target_caps));
    capsstruct = gst_caps_get_structure (target_caps, 0);

    /*                  v
     * application/quic+stream
     *                  ^
     */
    if (gst_structure_get_name (capsstruct)[17] == 's') {
      gchar *capsdebug;

      stream = quic_mux_get_stream_from_pad (mux, pad);
      g_assert (stream);

      gst_structure_set (capsstruct, QUICLIB_STREAMID_KEY, G_TYPE_UINT64,
          stream->stream_id, NULL);

      capsdebug = gst_caps_to_string (target_caps);
      GST_DEBUG_OBJECT (mux, "SRC pad caps for stream ID %lu: %s",
          stream->stream_id, capsdebug);
      g_free (capsdebug);
    } else {
      gchar *capsdebug = gst_caps_to_string (target_caps);
      GST_DEBUG_OBJECT (mux, "SRC pad caps for datagram: %s", capsdebug);
      g_free (capsdebug);
    }

    gst_query_set_caps_result (query, target_caps);

    gst_caps_unref (template_caps);

    break;
  }
  default:
    rv = gst_pad_query_default (pad, parent, query);
    return rv;
  }
  return TRUE;
}

/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
static gboolean
quicmux_init (GstPlugin * quicmux)
{
  /* debug category for filtering log messages
   *
   * exchange the string 'Template quicmux' with your description
   */
  GST_DEBUG_CATEGORY_INIT (gst_quic_mux_debug, "quicmux",
      0, "QUIC Multiplexer debugging");

  return GST_ELEMENT_REGISTER (quic_mux, quicmux);
}

/* PACKAGE: this is usually set by meson depending on some _INIT macro
 * in meson.build and then written into and defined in config.h, but we can
 * just set it ourselves here in case someone doesn't use meson to
 * compile this code. GST_PLUGIN_DEFINE needs PACKAGE to be defined.
 */
#ifndef PACKAGE
#define PACKAGE "quicmux"
#endif

/* gstreamer looks for this structure to register quicmuxs
 *
 * exchange the string 'Template quicmux' with your quicmux description
 */
GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    quicmux,
    "QUIC Multiplexer",
    quicmux_init,
    PACKAGE_VERSION, GST_LICENSE, GST_PACKAGE_NAME, GST_PACKAGE_ORIGIN)
