/*
 * GStreamer
 * Copyright (C) 2005 Thomas Vander Stichele <thomas@apestaart.org>
 * Copyright (C) 2005 Ronald S. Bultje <rbultje@ronald.bitfreak.net>
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

/**
 * SECTION:gstquicdemux
 * @title: GstQuicDemux
 * @short description: Deultiplex data received from a QUIC transport connection
 *
 * The quicdemux element takes the output of the quicsrc element and
 * demultiplexes it onto individual stream and datagram pads. It requires
 * buffers coming from upstream to be tagged with GstQuicLibStreamMeta to
 * identify stream frame data or GstQuicLibDatagramMeta to identify datagram
 * frame data.
 *
 * For streams, the quicdemux element creates a new src pad for each new stream
 * that it sees, and attempts to link it to a downstream element. It does this
 * by having an internal reference of all element instances that have been
 * linked to a src pad (peers) of this instance of the quicdemux element. It
 * then sends a custom query to each of those elements directly, and includes a
 * reference to the first buffer. This allows those peer elements to decide
 * whether they are interested in the new stream that is being opened. The peer
 * instances are queried in the order which they were first seen, and the first
 * peer element to declare an interest in the stream is the only peer element
 * instance that will be offered a new pad to link against.
 *
 * In order to facilitate populating the quicdemux instance with elements, the
 * element will try to optimistically open a stream and a datagram pad on
 * transition into the PAUSED state, i.e. before any actual data starts arriving
 * from the quicsrc element. When running on the command line under
 * gst-launch-1.0, the gst-launch-1.0 application performs hotplugging of
 * elements until the pipeline enters the PLAYING state. Therefore, having
 * quicdemux ! $element as part of the pipeline will be enough to ensure that
 * element is queried. When running under a custom application, the
 * gst_quic_demux_add_peer (and gst_quic_demux_remove_peer) methods can be
 * called to add and remove peers.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gst/gst.h>

#include "gstquicdemux.h"
#include "gstquicstream.h"
#include "gstquicdatagram.h"
#include "gstquicstreamextras.h"

#include "config.h"

GST_DEBUG_CATEGORY_STATIC (gst_quic_demux_debug);
#define GST_CAT_DEFAULT gst_quic_demux_debug

enum {
  SIGNAL_ADD_PEER,
  SIGNAL_REMOVE_PEER,
  LAST_SIGNAL
};

static guint gst_quic_demux_signals[LAST_SIGNAL] = { 0 };

/* the capabilities of the inputs and outputs.
 *
 * describe the real formats here.
 */
static GstStaticPadTemplate sink_factory =
    GST_STATIC_PAD_TEMPLATE ("sink", GST_PAD_SINK, GST_PAD_ALWAYS,
        GST_STATIC_CAPS (QUICLIB_RAW));

static GstStaticPadTemplate bidi_streamsrc_factory =
		GST_STATIC_PAD_TEMPLATE ("bidi_stream_src_%u", GST_PAD_SRC,
			GST_PAD_SOMETIMES, GST_STATIC_CAPS (QUICLIB_BIDI_STREAM_CAP));

static GstStaticPadTemplate uni_streamsrc_factory =
		GST_STATIC_PAD_TEMPLATE ("uni_stream_src_%u", GST_PAD_SRC,
		    GST_PAD_SOMETIMES, GST_STATIC_CAPS (QUICLIB_UNI_STREAM_CAP));

static GstStaticPadTemplate datagramsrc_factory =
		GST_STATIC_PAD_TEMPLATE ("datagram_src_%u", GST_PAD_SRC,
		    GST_PAD_SOMETIMES, GST_STATIC_CAPS (QUICLIB_DATAGRAM_CAP));

#define gst_quic_demux_parent_class parent_class
G_DEFINE_TYPE_WITH_PRIVATE (GstQuicDemux, gst_quic_demux, GST_TYPE_ELEMENT);

GST_ELEMENT_REGISTER_DEFINE (quic_demux, "quicdemux", GST_RANK_NONE,
    GST_TYPE_QUICDEMUX);

static void gst_quic_demux_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec);
static void gst_quic_demux_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec);

static GstStateChangeReturn gst_quic_demux_change_state (GstElement *elem,
    GstStateChange t);

static gboolean gst_quic_demux_sink_event (GstPad * pad,
    GstObject * parent, GstEvent * event);
static GstFlowReturn gst_quic_demux_chain (GstPad * pad,
    GstObject * parent, GstBuffer * buf);
static gboolean gst_quic_demux_query (GstPad *pad, GstObject *parent,
    GstQuery *query);

static GstPad * quic_demux_open_stream_srcpad (GstQuicDemux *demux,
    guint64 stream_id, GstElement *target_peer);
static gboolean quic_demux_open_datagram_srcpad (GstQuicDemux *demux,
    GstElement *target_peer);

static gboolean quic_demux_close_stream_srcpad (GstQuicDemux *demux,
    GstPad *pad, guint64 stream_id);
static gboolean quic_demux_close_datagram_srcpad (GstQuicDemux *demux);

void quic_demux_pad_linked (GstPad *self, GstPad *peer, gpointer user_data);
void quic_demux_pad_unlinked (GstPad *self, GstPad *peer, gpointer user_data);

void quic_demux_stream_hash_destroy (GstPad *sink);

/* GObject vmethod implementations */

/* initialize the quicdemux's class */
static void
gst_quic_demux_class_init (GstQuicDemuxClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class;

  gobject_class = (GObjectClass *) klass;
  gstelement_class = (GstElementClass *) klass;

  gobject_class->set_property = gst_quic_demux_set_property;
  gobject_class->get_property = gst_quic_demux_get_property;

  gstelement_class->change_state = gst_quic_demux_change_state;

  klass->add_peer = GST_DEBUG_FUNCPTR (gst_quic_demux_add_peer);
  klass->remove_peer = GST_DEBUG_FUNCPTR (gst_quic_demux_remove_peer);

  gst_element_class_set_static_metadata (gstelement_class,
      "QUIC Transport Demultiplexer",
      "Demuxer/Network",
      "Work in tandem with a quicsrc element to demultiplex data flows from "
      "QUIC transport streams and datagrams",
      "Sam Hurst <sam.hurst@bbc.co.uk>");

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&sink_factory));

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&bidi_streamsrc_factory));

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&uni_streamsrc_factory));

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&datagramsrc_factory));

  gst_quic_demux_signals[SIGNAL_ADD_PEER] =
      g_signal_new ("add-peer", G_TYPE_FROM_CLASS (klass),
          G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
          G_STRUCT_OFFSET (GstQuicDemuxClass, add_peer), NULL, NULL, NULL,
          G_TYPE_BOOLEAN, 1, GST_TYPE_ELEMENT);

  gst_quic_demux_signals[SIGNAL_REMOVE_PEER] =
      g_signal_new ("remove-peer", G_TYPE_FROM_CLASS (klass),
          G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
          G_STRUCT_OFFSET (GstQuicDemuxClass, remove_peer), NULL, NULL, NULL,
          G_TYPE_BOOLEAN, 1, GST_TYPE_ELEMENT);
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad callback functions
 * initialize instance structure
 */
static void
gst_quic_demux_init (GstQuicDemux * demux)
{
  GstQuicDemuxPrivate *priv = gst_quic_demux_get_instance_private (demux);

  g_rec_mutex_init (&priv->mutex);

  priv->stream_srcpads = g_hash_table_new_full (g_int64_hash, g_int64_equal,
      g_free, (GDestroyNotify) quic_demux_stream_hash_destroy);
  priv->sinkpad = gst_pad_new_from_static_template (
		  &sink_factory, "sink");
  gst_pad_set_event_function (priv->sinkpad,
      GST_DEBUG_FUNCPTR (gst_quic_demux_sink_event));
  gst_pad_set_chain_function (priv->sinkpad,
      GST_DEBUG_FUNCPTR (gst_quic_demux_chain));
  gst_pad_set_query_function (priv->sinkpad,
      GST_DEBUG_FUNCPTR (gst_quic_demux_query));
  GST_PAD_SET_PROXY_CAPS (priv->sinkpad);
  gst_element_add_pad (GST_ELEMENT (demux), priv->sinkpad);
}

static void
gst_quic_demux_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  /*GstQuicDemux *demux = GST_QUICDEMUX (object);*/

  switch (prop_id) {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_quic_demux_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  /*GstQuicDemux *filter = GST_QUICDEMUX (object);*/

  switch (prop_id) {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static GstStateChangeReturn
gst_quic_demux_change_state (GstElement *elem, GstStateChange t)
{
  GstQuicDemux *demux = GST_QUICDEMUX (elem);
  GstQuicDemuxPrivate *priv = gst_quic_demux_get_instance_private (demux);

  GST_TRACE_OBJECT (demux, "Changing state from %s to %s",
      gst_element_state_get_name ((t & 0xf8) >> 3),
      gst_element_state_get_name (t & 0x7));

  GstStateChangeReturn rv =
      GST_ELEMENT_CLASS (parent_class)->change_state (elem, t);

  /* Attempt to connect downstream elements to find peers */
  if (t == GST_STATE_CHANGE_READY_TO_PAUSED) {
    GstPad *pad;
    GstQuery *q;
    GstQUICMode mode;

    /* Query quicsrc as to whether it's in client or server mode */
    q = gst_query_new_quiclib_conn_state ();

    if (!gst_pad_query (gst_pad_get_peer (priv->sinkpad), q)) {
      GST_WARNING_OBJECT (demux, "Couldn't query src mode!");
      gst_query_unref (q);
      return rv;
    }

    if (!gst_query_parse_quiclib_conn_state (q, &mode, NULL, NULL, NULL)) {
      GST_WARNING_OBJECT (demux, "Couldn't parse connection state query");
      gst_query_unref (q);
      return rv;
    }

    gst_query_unref (q);

    /* Try opening a bidi stream */
    pad = quic_demux_open_stream_srcpad (demux,
        (mode == QUICLIB_MODE_SERVER)?(0):(1), NULL);
    if (pad != NULL) {
      if (gst_pad_is_linked (pad)) {
        gst_quic_demux_add_peer (demux,
            GST_ELEMENT (gst_pad_get_parent (gst_pad_get_peer (pad))));
        priv->peer_support |= BIDI_STREAM_SUPPORTED;
      }
      quic_demux_close_stream_srcpad (demux, pad,
          (mode == QUICLIB_MODE_SERVER)?(0):(1));
    }

    /* Try opening a uni stream */
    pad = quic_demux_open_stream_srcpad (demux,
        (mode == QUICLIB_MODE_SERVER)?(2):(3), NULL);
    if (pad != NULL) {
      if (gst_pad_is_linked (pad)) {
        gst_quic_demux_add_peer (demux,
            GST_ELEMENT (gst_pad_get_parent (gst_pad_get_peer (pad))));
        priv->peer_support |= UNI_STREAM_SUPPORTED;
      }

      quic_demux_close_stream_srcpad (demux, pad,
          (mode == QUICLIB_MODE_SERVER)?(2):(3));
    }

    /* Try opening a datagram pad */
    if (quic_demux_open_datagram_srcpad (demux, NULL)) {
      if (gst_pad_is_linked (priv->datagram_srcpad)) {
        gst_quic_demux_add_peer (demux, GST_ELEMENT (gst_pad_get_parent (
            gst_pad_get_peer (priv->datagram_srcpad))));
        priv->peer_support |= DATAGRAM_SUPPORTED;
      }
    }

    quic_demux_close_datagram_srcpad (demux);
  }

  return rv;
}

void
quic_demux_pad_linked_callback (GstPad *self, GstPad *peer,
    gpointer user_data)
{
  GstQuicDemux *demux;
  GstQuicDemuxPrivate *priv;
  GstElement *peer_elem;
  GList *it;
  gboolean exists = FALSE;

  demux = GST_QUICDEMUX (gst_pad_get_parent (self));
  priv = gst_quic_demux_get_instance_private (demux);
  peer_elem = GST_ELEMENT (gst_pad_get_parent (peer));

  for (it = priv->peers; it != NULL; it = it->next) {
    if (it->data == (gpointer) peer_elem) {
      exists = TRUE;
      break;
    }
  }

  if (!exists) {
    gst_quic_demux_add_peer (demux, peer_elem);
  }
}

static gboolean
forward_sticky_events (GstPad *pad, GstEvent **event, gpointer user_data)
{
  g_return_val_if_fail (GST_IS_EVENT (*event), FALSE);

  if ((*event)->type != GST_EVENT_CAPS) {
    GST_LOG_OBJECT (GST_QUICDEMUX (gst_pad_get_parent (pad)),
        "Forwarding sticky event type %s", GST_EVENT_TYPE_NAME (*event));

    gst_event_ref (*event);

    return gst_pad_push_event (GST_PAD (user_data), *event);
  }
  return TRUE;
}

static GstPad *
quic_demux_open_stream_srcpad (GstQuicDemux *demux, guint64 stream_id,
    GstElement *target_peer)
{
  GstQuicDemuxPrivate *priv;
  GstCaps *caps;
  GstPadTemplate *template;
  GstPad *pad;
  GstStream *stream;
  GstSegment *segment;
  GstEvent *event;
  gchar *pad_name, *stream_name;
  gint64 *stream_id_ptr;
  GstPadLinkReturn rv;

  priv = gst_quic_demux_get_instance_private (demux);

  if (gst_quiclib_get_stream_type_from_id (stream_id) == QUIC_STREAM_BIDI) {
    template = gst_static_pad_template_get (&bidi_streamsrc_factory);
    caps = gst_caps_new_simple (QUICLIB_BIDI_STREAM_CAP,
          QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id, NULL);
    stream_name = g_strdup_printf ("quicdemux_bidi_%lu", stream_id);
  } else {
    template = gst_static_pad_template_get (&uni_streamsrc_factory);
    caps = gst_caps_new_simple (QUICLIB_UNI_STREAM_CAP,
          QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id, NULL);
    stream_name = g_strdup_printf ("quicdemux_uni_%lu", stream_id);
  }

  pad_name = g_strdup_printf (template->name_template, stream_id);

  pad = gst_pad_new_from_template (template, pad_name);

  stream = gst_stream_new (stream_name, caps, GST_STREAM_TYPE_UNKNOWN,
      GST_STREAM_FLAG_NONE);

  gst_pad_set_active (pad, TRUE);
  gst_pad_use_fixed_caps (pad);

  event = gst_pad_get_sticky_event (priv->sinkpad, GST_EVENT_STREAM_START, 0);
  if (event) {
    gst_event_unref (event);
  }
  event = gst_event_new_stream_start (stream_name);
  gst_event_set_stream (event, stream);
  gst_stream_set_caps (stream, caps);

  gst_pad_push_event (pad, event);

  gst_pad_set_caps (pad, caps);
  gst_pad_set_query_function (pad, gst_quic_demux_query);

  gst_element_add_pad (GST_ELEMENT (demux), pad);

  if (!gst_pad_is_linked (pad) && target_peer != NULL) {
    GstPadTemplate *peer_template;
    GstPad *peer_pad;
    GstCaps *pad_caps, *peer_pad_caps, *peer_allowed_caps;

    peer_template = gst_element_get_compatible_pad_template (target_peer,
        template);

    GST_DEBUG_OBJECT (demux, "Got pad template %" GST_PTR_FORMAT, peer_template);

    peer_pad = gst_element_request_pad (target_peer, peer_template, NULL, caps);
    g_warn_if_fail (peer_pad);

    pad_caps = gst_pad_get_current_caps (pad);
    peer_pad_caps = gst_pad_get_current_caps (peer_pad);
    peer_allowed_caps = gst_pad_get_allowed_caps (peer_pad);

    GST_DEBUG_OBJECT (demux, "Pad template caps: %" GST_PTR_FORMAT
        " - peer template caps: %" GST_PTR_FORMAT
        " - pad caps: %" GST_PTR_FORMAT " - peer pad caps: %" GST_PTR_FORMAT
        " - peer allowed caps: %" GST_PTR_FORMAT,
        GST_PAD_TEMPLATE_CAPS (template), GST_PAD_TEMPLATE_CAPS (peer_template),
        pad_caps, peer_pad_caps, peer_allowed_caps);

    if (pad_caps) gst_caps_unref (pad_caps);
    if (peer_pad_caps) gst_caps_unref (peer_pad_caps);
    if (peer_allowed_caps) gst_caps_unref (peer_allowed_caps);

    rv = gst_pad_link (pad, peer_pad);
    if (rv != GST_PAD_LINK_OK) {
      GST_ERROR_OBJECT (demux,
          "Could not link pads (%" GST_PTR_FORMAT " -> %" GST_PTR_FORMAT ")",
          pad, peer_pad);
      g_free (pad_name);
      g_free (stream_name);
      gst_object_unref (template);
      gst_caps_unref (caps);
      gst_object_unref (pad);
      gst_object_unref (peer_pad);
      return NULL;
    }

    GST_DEBUG_OBJECT (demux,
        "Successfully linked pad %" GST_PTR_FORMAT " to %" GST_PTR_FORMAT,
        pad, peer_pad);
  }

  gst_object_unref (template);
  gst_caps_unref (caps);
  g_free (pad_name);
  g_free (stream_name);

  segment = g_new0 (GstSegment, 1);
  gst_segment_init (segment, GST_FORMAT_TIME);
  event = gst_event_new_segment (segment);
  gst_pad_push_event (pad, event);

  stream_id_ptr = g_new (gint64, 1);
  *stream_id_ptr = stream_id;

  GST_DEBUG_OBJECT (demux, "Adding stream context to hash table for stream ID "
      "%lu with pad %p / %" GST_PTR_FORMAT, stream_id, pad, pad);

  g_rec_mutex_lock (&priv->mutex);
  g_hash_table_insert (priv->stream_srcpads, stream_id_ptr, (gpointer) pad);
  g_rec_mutex_unlock (&priv->mutex);

  return pad;
}

static gboolean
quic_demux_open_datagram_srcpad (GstQuicDemux *demux, GstElement *target_peer)
{
  GstQuicDemuxPrivate *priv = gst_quic_demux_get_instance_private (demux);

  g_rec_mutex_lock (&priv->mutex);
  priv->datagram_srcpad =
      gst_pad_new_from_static_template (&datagramsrc_factory, "dg_src");

  gst_element_add_pad (GST_ELEMENT (demux), priv->datagram_srcpad);

  gst_pad_set_active (priv->datagram_srcpad, TRUE);

  if (!gst_pad_is_linked (priv->datagram_srcpad) && target_peer != NULL) {
    if (!gst_element_link_pads (GST_ELEMENT (demux),
        GST_PAD_NAME (priv->datagram_srcpad), target_peer, NULL)) {
      gst_element_remove_pad (GST_ELEMENT (demux), priv->datagram_srcpad);
      priv->datagram_srcpad = NULL;
      g_rec_mutex_unlock (&priv->mutex);
      return FALSE;
    }
  }

  gst_pad_sticky_events_foreach (priv->sinkpad, forward_sticky_events,
      priv->datagram_srcpad);

  g_rec_mutex_unlock (&priv->mutex);

  return TRUE;
}

static gboolean
quic_demux_close_stream_srcpad (GstQuicDemux *demux, GstPad *pad,
    guint64 stream_id)
{
  GstQuicDemuxPrivate *priv = gst_quic_demux_get_instance_private (demux);

  g_rec_mutex_lock (&priv->mutex);

  if (pad == NULL && !g_hash_table_lookup_extended (priv->stream_srcpads,
                                        &stream_id, NULL, (gpointer *) &pad)) {
    GST_DEBUG_OBJECT (demux,
        "Couldn't find srcpad for stream ID %lu - has it been closed already?",
        stream_id);
    g_rec_mutex_unlock (&priv->mutex);
    return FALSE;
  }

  GST_DEBUG_OBJECT (demux, "Closing pad %p on account of stream ID %lu closing",
      pad, stream_id);

  g_return_val_if_fail (pad, FALSE);

  g_hash_table_remove (priv->stream_srcpads, &stream_id);

  g_assert (g_hash_table_lookup (priv->stream_srcpads, &stream_id) == NULL);

  g_rec_mutex_unlock (&priv->mutex);

  return TRUE;
}

static gboolean
quic_demux_close_datagram_srcpad (GstQuicDemux *demux)
{
  GstQuicDemuxPrivate *priv;
  gboolean rv = FALSE;

  priv = gst_quic_demux_get_instance_private (demux);

  g_rec_mutex_lock (&priv->mutex);

  if (priv->datagram_srcpad) {
    gst_element_remove_pad (GST_ELEMENT (demux), priv->datagram_srcpad);
    rv = TRUE;
  }

  g_rec_mutex_unlock (&priv->mutex);

  return rv;
}

/* GstElement vmethod implementations */

/* this function handles sink events */
static gboolean
gst_quic_demux_sink_event (GstPad * pad, GstObject * parent,
    GstEvent * event)
{
  GstQuicDemux *demux;
  GstQuicDemuxPrivate *priv;
  gboolean ret;

  demux = GST_QUICDEMUX (parent);
  priv = gst_quic_demux_get_instance_private (demux);

  GST_LOG_OBJECT (demux, "Received %s event: %" GST_PTR_FORMAT,
      GST_EVENT_TYPE_NAME (event), event);

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_CAPS:
    {
      GstCaps *caps;

      gst_event_parse_caps (event, &caps);
      /* do something with the caps */

      /* and forward */
      ret = gst_pad_event_default (pad, parent, event);
      break;
    }
    case GST_EVENT_EOS:
    {
      GList *it;

      gst_event_ref (event);

      for (it = priv->peers; it != NULL; it = it->next) {
        gst_element_send_event (GST_ELEMENT (it->data), event);
      }

      gst_event_unref (event);

      ret = gst_pad_event_default (pad, parent, event);
      break;
    }
    case GST_EVENT_CUSTOM_DOWNSTREAM:
    {
      const GstStructure *structure = gst_event_get_structure (event);
      g_return_val_if_fail (structure, FALSE);

      if (gst_event_has_name (event, QUICLIB_HANDSHAKE_COMPLETE)) {
        gchar *alpn;

        g_return_val_if_fail (gst_quiclib_parse_handshake_complete_event (
            event, NULL, &alpn), FALSE);

        GST_DEBUG_OBJECT (demux, "Handshake complete for %s connection", alpn);

        g_free (alpn);
      } else if (gst_event_has_name (event, QUICLIB_CONNECTION_CLOSE)) {
        GST_INFO_OBJECT (demux, "Connection closing, TODO how to handle?");
        g_assert (0);

      } else if (gst_event_has_name (event, QUICLIB_STREAM_OPEN)) {
        guint64 stream_id;

        g_return_val_if_fail (gst_quiclib_parse_stream_opened_event (event,
            &stream_id), FALSE);

        GST_DEBUG_OBJECT (demux, "Stream %lu opened", stream_id);

        /*
         * Request a new pad
         */


        ret = TRUE;
      } else if (gst_event_has_name (event, QUICLIB_STREAM_CLOSE)) {
        guint64 stream_id;

        g_return_val_if_fail (gst_quiclib_parse_stream_closed_event (event,
            &stream_id), FALSE);

        ret = quic_demux_close_stream_srcpad (demux, NULL, stream_id);
      } else {
        GST_INFO_OBJECT (demux, "Unknown custom downstream event \"%s\"",
            gst_structure_get_name (structure));
        ret = gst_pad_event_default (pad, parent, event);
      }

      break;
    }
    default:
      ret = gst_pad_event_default (pad, parent, event);
      break;
  }

  return ret;
}

static gboolean
gst_quic_demux_query (GstPad *pad, GstObject *parent, GstQuery *query)
{
  GstQuicDemux *demux = GST_QUICDEMUX (parent);
  GstQuicDemuxPrivate *priv = gst_quic_demux_get_instance_private (demux);
  const gchar *query_type = GST_QUERY_TYPE_NAME (query);
  GstStructure *s;
  gboolean rv = TRUE;

  GST_LOG_OBJECT (demux, "Received %s query from %s pad %s", query_type,
      (gst_pad_get_direction (pad) == GST_PAD_SRC)?("src"):((
          gst_pad_get_direction (pad) == GST_PAD_SINK)?("sink"):("unknown")),
      GST_PAD_NAME (pad));

  switch (GST_QUERY_TYPE (query)) {
  case GST_QUERY_CUSTOM:
    if (gst_pad_get_direction (pad) == GST_PAD_SINK) {
      g_return_val_if_fail (gst_query_is_writable (query), FALSE);

      s = gst_query_writable_structure (query);

      g_return_val_if_fail (s, FALSE);

      if (gst_structure_has_name (s, QUICLIB_CLIENT_CONNECT)) {
      } else if (gst_structure_has_name (s, QUICLIB_HANDSHAKE_COMPLETE)) {
      } else if (gst_structure_has_name (s, QUICLIB_STREAM_OPEN)) {
        /* Request a new pad */

      }
    } else if (gst_pad_get_direction (pad) == GST_PAD_SRC) {
      if (gst_query_is_associated_stream_id (query)) {
        GstPad *local_pad;
        GHashTableIter iter;
        gpointer ht_key, ht_value;
        guint64 stream_id = G_MAXUINT64;

        local_pad = gst_query_get_associated_stream_id_pad (query,
            GST_ELEMENT (demux));

        if (local_pad == NULL) {
          return FALSE;
        }

        g_hash_table_iter_init (&iter, priv->stream_srcpads);
        while (g_hash_table_iter_next (&iter, &ht_key, &ht_value)) {
          if ((GstPad *) ht_value == local_pad) {
            stream_id = *((guint64 *) ht_key);
            break;
          }
        }

        if (stream_id != G_MAXUINT64) {
          return gst_query_fill_get_associated_stream_id (query, stream_id);
        }
      } else if (gst_query_is_associated_pad (query)) {
        guint64 sid;
        GList *it;

        sid = gst_query_get_associated_pad_stream_id (query);

        pad = (GstPad *) g_hash_table_lookup (priv->stream_srcpads, &sid);

        if (pad) {
          return gst_query_fill_get_associated_pad (query, pad);
        }
      }
    }
    break;
  case GST_QUERY_ACCEPT_CAPS:
  {
    GstCaps *caps, *templ_caps;

    gst_query_parse_accept_caps (query, &caps);

    GST_DEBUG_OBJECT (demux, "Trying accept caps of %" GST_PTR_FORMAT, caps);

    templ_caps = gst_pad_get_pad_template_caps (pad);
    templ_caps = gst_caps_make_writable (templ_caps);

    if (gst_caps_can_intersect (caps, templ_caps)) {
      GST_DEBUG_OBJECT (demux, "Caps %" GST_PTR_FORMAT " intersection with %"
          GST_PTR_FORMAT " accepted", caps, templ_caps);
    } else {
      GST_DEBUG_OBJECT (demux,
          "Caps %" GST_PTR_FORMAT " couldn't intersect with %" GST_PTR_FORMAT,
          caps, templ_caps);
      rv = FALSE;
    }

    gst_caps_unref (templ_caps);

    gst_query_set_accept_caps_result (query, rv);
    rv = TRUE;

    break;
  }
  case GST_QUERY_CAPS:
  {
    GstCaps *temp, *caps, *filt, *tcaps;

    if (gst_pad_get_direction (pad) == GST_PAD_SINK) {
      caps = gst_pad_template_get_caps (
          gst_element_get_pad_template (GST_ELEMENT (parent), "sink"));
    } else {
      caps = gst_caps_new_simple (QUICLIB_BIDI_STREAM_CAP, NULL, NULL);
      gst_caps_append (caps, gst_caps_new_simple (QUICLIB_UNI_STREAM_CAP, NULL,
          NULL));
      gst_caps_append (caps, gst_caps_new_simple (QUICLIB_DATAGRAM_CAP, NULL,
          NULL));
    }

    gst_query_parse_caps (query, &filt);

    tcaps = gst_pad_get_pad_template_caps (pad);
    if (tcaps) {
      temp = gst_caps_intersect (caps, tcaps);
      gst_caps_unref (caps);
      gst_caps_unref (tcaps);
      caps = temp;
    }

    if (filt) {
      temp = gst_caps_intersect (caps, filt);
      gst_caps_unref (caps);
      caps = temp;
    }
    gst_query_set_caps_result (query, caps);
    gst_caps_unref (caps);
    rv = TRUE;
    break;
  }
  default:
    rv = gst_pad_query_default (pad, GST_OBJECT (demux), query);
  }

  return rv;
}

/* chain function
 * this function does the actual processing
 */
static GstFlowReturn
gst_quic_demux_chain (GstPad * pad, GstObject * parent, GstBuffer * buf)
{
  GstQuicDemux *demux = GST_QUICDEMUX (parent);
  GstQuicDemuxPrivate *priv = gst_quic_demux_get_instance_private (demux);
  GstQuicLibStreamMeta *stream;
  GstQuicLibDatagramMeta *datagram;
  GstPad *target_pad;
  GstFlowReturn rv;

  g_rec_mutex_lock (&priv->mutex);

  GST_QUICLIB_PRINT_BUFFER (demux, buf);

  stream = gst_buffer_get_quiclib_stream_meta (buf);
  if (stream != NULL) {
    if (!g_hash_table_lookup_extended (priv->stream_srcpads,
        &stream->stream_id, NULL, (gpointer *) &target_pad)) {
      /*
       * Any new pads are added to demux->stream_srcpads in
       * quic_demux_open_stream_srcpad
       */
      GstQuery *query;
      GList *it;

      if (stream->final && gst_buffer_get_size (buf) == 0) {
        GST_TRACE_OBJECT (demux, "Seen 0-length final buffer with no stream");
        /*
         * We've probably already seen the final packet for this stream and this
         * is a spurious extra. Even if we haven't, it's got no length and is
         * marked final, so we can probably just drop it.
         */
        g_rec_mutex_unlock (&priv->mutex);
        return GST_FLOW_OK;
      }

      GST_DEBUG_OBJECT (demux, "Buffer for stream %ld with no peer - "
          "querying %u peers for new stream", stream->stream_id,
          g_list_length (priv->peers));

      if (QUICLIB_STREAM_IS_UNI (stream->stream_id)) {
        GstMapInfo map;
        guint64 stream_type;

        gst_buffer_map (buf, &map, GST_MAP_READ);

        gst_quiclib_get_varint (map.data, &stream_type);

        gst_buffer_unmap (buf, &map);

        query = gst_query_new_custom (GST_QUERY_CUSTOM,
            gst_structure_new (QUICLIB_STREAM_OPEN,
                QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream->stream_id,
                "stream-buf-peek", G_TYPE_POINTER, (gpointer) buf,
                "uni-stream-type", G_TYPE_UINT64, stream_type,
                NULL));
      } else {
        query = gst_query_new_custom (GST_QUERY_CUSTOM,
            gst_structure_new (QUICLIB_STREAM_OPEN,
                QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream->stream_id,
                "stream-buf-peek", G_TYPE_POINTER, (gpointer) buf,
                NULL));
      }

      for (it = priv->peers; it != NULL; it = it->next) {
        if (gst_element_query (GST_ELEMENT (it->data), query)) {
          target_pad = quic_demux_open_stream_srcpad (demux, stream->stream_id,
              GST_ELEMENT (it->data));
          break;
        }
      }

      if (target_pad == NULL && priv->peers == NULL) {
        /* Optimisitically try to link to anything */
        target_pad = quic_demux_open_stream_srcpad (demux, stream->stream_id,
            NULL);

        if (gst_pad_is_linked (target_pad)) {
          gst_quic_demux_add_peer (demux, GST_ELEMENT (gst_pad_get_parent
              (gst_pad_get_peer (target_pad))));
        } else {
          g_rec_mutex_unlock (&priv->mutex);
          return GST_FLOW_NOT_LINKED;
        }
      }


    }
  }

  datagram = gst_buffer_get_quiclib_datagram_meta (buf);
  if (datagram != NULL) {
    if (priv->datagram_srcpad == NULL) {
      GstQuery *query;
      GList *it;

      query = gst_query_new_custom (GST_QUERY_CUSTOM,
          gst_structure_new (QUICLIB_DATAGRAM, NULL, NULL));
      for (it = priv->peers; it != NULL; it = it->next) {
        if (gst_element_query (GST_ELEMENT (it->data), query)) {
          quic_demux_open_datagram_srcpad (demux, GST_ELEMENT (it->data));
        }
      }
    }

    target_pad = priv->datagram_srcpad;
  }

  /*g_assert (target_pad);*/
  if (target_pad == NULL || !gst_pad_is_linked (target_pad)) {
    /* Nothing interested in this stream or datagram  - TODO cancel stream? */
    return GST_FLOW_OK;
  }

  /*if (!gst_pad_is_linked (target_pad)) {*/
  if (1) {
    GstBin *pipeline = GST_BIN (gst_element_get_parent (demux));

    while (!GST_IS_PIPELINE (pipeline)) {
      GST_TRACE_OBJECT (demux, "Bin %s (%p) is not pipeline, going up...",
          gst_element_get_name (pipeline), pipeline);
      pipeline = GST_BIN (gst_element_get_parent (pipeline));
    }

    GST_TRACE_OBJECT (demux, "Found pipeline %s (%p)",
        gst_element_get_name (pipeline), pipeline);

    gst_debug_bin_to_dot_file_with_ts (pipeline, GST_DEBUG_GRAPH_SHOW_ALL,
        "quicdemux-pad"/*-unlinked-error"*/);
  }
  g_assert (gst_pad_is_linked (target_pad));

  g_rec_mutex_unlock (&priv->mutex);

  rv = gst_pad_push (target_pad, buf);

  GST_DEBUG_OBJECT (demux, "Push result: %d", rv);

  if (stream && stream->final) {
    GST_DEBUG_OBJECT (demux, "Closing pad %p for stream ID %lu", target_pad,
        stream->stream_id);
    quic_demux_close_stream_srcpad (demux, target_pad, stream->stream_id);
  }

  return rv;
}

/*void
quic_demux_pad_linked (GstPad *self, GstPad *peer, gpointer user_data)
{
  gst_quic_demux_add_peer (GST_QUICDEMUX (gst_pad_get_parent (self)),
      GST_ELEMENT (gst_pad_get_parent (peer)));
}

gboolean
quic_demux_find_pad (gint64* key, GstPad *value, GstPad *search)
{
  if (value == search) return TRUE;
  return FALSE;
}

void
quic_demux_pad_unlinked (GstPad *self, GstPad *peer, gpointer user_data)
{
  GstQuicDemux *quicdemux = GST_QUICDEMUX (gst_pad_get_parent (self));
  guint rv;

  g_rec_mutex_lock (&quicdemux->mutex);

  rv = g_hash_table_find (quicdemux->stream_srcpads,
      (GHRFunc) quic_demux_find_pad, (gpointer) self);

  GST_TRACE_OBJECT (quicdemux,
      "Removed %u entries from the stream hash table relating to pad %p", rv,
      self);

  g_rec_mutex_unlock (&quicdemux->mutex);
}*/

void
quic_demux_stream_hash_destroy (GstPad *sink)
{
  gst_element_remove_pad (GST_ELEMENT (gst_pad_get_parent (sink)), sink);
}

gboolean
gst_quic_demux_add_peer (GstQuicDemux *demux, GstElement *peer)
{
  GstQuicDemuxPrivate *priv;
  GList *it;

  priv = gst_quic_demux_get_instance_private (demux);

  g_rec_mutex_lock (&priv->mutex);

  for (it = priv->peers; it != NULL; it = it->next) {
    if (it->data == (gpointer) peer) {
      g_rec_mutex_unlock (&priv->mutex);
      return FALSE;
    }
  }

  priv->peers = g_list_append (priv->peers, (gpointer) peer);

  g_rec_mutex_unlock (&priv->mutex);

  return TRUE;
}

gboolean
gst_quic_demux_remove_peer (GstQuicDemux *demux, GstElement *peer)
{
  gboolean rv = FALSE;
  GstQuicDemuxPrivate *priv;
  GList *it;

  priv = gst_quic_demux_get_instance_private (demux);
  it = priv->peers;

  g_rec_mutex_lock (&priv->mutex);

  for (; it != NULL; it = it->next) {
    if (it->data == peer) {
      priv->peers = g_list_delete_link (priv->peers, it);
      rv = TRUE;
      break;
    }
  }

  g_rec_mutex_unlock (&priv->mutex);

  return rv;
}

GstQuery *
gst_quic_demux_open_bidi_stream_query_new (GstQuicDemux *demux,
    guint64 stream_id, GstBuffer *peek)
{
  return gst_query_new_custom (GST_QUERY_CUSTOM,
      gst_structure_new (QUICLIB_STREAM_OPEN,
          QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id,
          "stream-buf-peek", G_TYPE_POINTER, (gpointer) peek,
          NULL));
}

GstQuery *
gst_quic_demux_open_uni_stream_query_new (GstQuicDemux *demux,
    guint64 stream_id, guint64 uni_stream_type, GstBuffer *peek)
{
  return gst_query_new_custom (GST_QUERY_CUSTOM,
      gst_structure_new (QUICLIB_STREAM_OPEN,
          QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id,
          "stream-buf-peek", G_TYPE_POINTER, (gpointer) peek,
          "uni-stream-type", G_TYPE_UINT64, uni_stream_type,
          NULL));
}

gboolean
gst_quic_demux_open_stream_query_parse (GstQuery *query, guint64 *stream_id,
    guint64 *uni_stream_type, GstBuffer **peek)
{
  const GstStructure *s;

  g_return_val_if_fail (query, FALSE);

  s = gst_query_get_structure (query);

  if (gst_structure_has_name (s, QUICLIB_STREAM_OPEN) == FALSE) {
    return FALSE;
  }

  if (stream_id != NULL) {
    g_return_val_if_fail (gst_structure_get_uint64 (s, QUICLIB_STREAMID_KEY,
        stream_id), FALSE);
  }

  if (uni_stream_type != NULL) {
    g_return_val_if_fail (gst_structure_get_uint64 (s, "uni-stream-type",
        uni_stream_type), FALSE);
  }

  if (peek != NULL) {
    const GValue * buf_box = gst_structure_get_value (s, "stream-buf-peek");
    g_return_val_if_fail (buf_box, FALSE);
    *peek = GST_BUFFER (g_value_get_pointer (buf_box));
  }

  return TRUE;
}

/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
static gboolean
quicdemux_init (GstPlugin * quicdemux)
{
  /* debug category for filtering log messages
   *
   * exchange the string 'Template quicdemux' with your description
   */
  GST_DEBUG_CATEGORY_INIT (gst_quic_demux_debug, "quicdemux",
      0, "Template quicdemux");

  return GST_ELEMENT_REGISTER (quic_demux, quicdemux);
}

/* PACKAGE: this is usually set by meson depending on some _INIT macro
 * in meson.build and then written into and defined in config.h, but we can
 * just set it ourselves here in case someone doesn't use meson to
 * compile this code. GST_PLUGIN_DEFINE needs PACKAGE to be defined.
 */
#ifndef PACKAGE
#define PACKAGE "quicdemux"
#endif

/* gstreamer looks for this structure to register quicdemuxs
 *
 * exchange the string 'Template quicdemux' with your quicdemux description
 */
GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    quicdemux,
    "quicdemux",
    quicdemux_init,
    PACKAGE_VERSION, GST_LICENSE, GST_PACKAGE_NAME, GST_PACKAGE_ORIGIN)

