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

#include "gstquicstream.h"
#include "gstquictransport.h"
#include "gstquiccommon.h"

gssize
gst_quiclib_transport_stream_send_raw (GstQuicLibTransportConnection *conn,
    guint64 stream_id, const guint *buf, const gsize buflen)
{
  return 0;
}

void
gst_quiclib_transport_stream_cancel (GstQuicLibTransportConnection *conn,
    guint64 stream_id)
{

}

GType
gst_quiclib_stream_meta_api_get_type (void)
{
  static gsize g_type = 0;
  static const gchar *tags[] = { NULL };

  if (g_once_init_enter (&g_type)) {
    const GType type = gst_meta_api_type_register ("GstQuicLibStreamMetaAPI",
        tags);
    g_once_init_leave (&g_type, type);
  }

  return g_type;
}

static gboolean
quiclib_stream_meta_init (GstMeta *meta, gpointer params, GstBuffer *buffer)
{
  GstQuicLibStreamMeta *streammeta = (GstQuicLibStreamMeta *) meta;

  streammeta->stream_id = -1;
  streammeta->stream_type = -1;
  streammeta->offset = 0;
  streammeta->length = 0;
  streammeta->final = FALSE;

  return TRUE;
}

static gboolean
quiclib_stream_meta_transform (GstBuffer *transbuf, GstMeta *meta,
    GstBuffer *buffer, GQuark type, gpointer data)
{
  GstQuicLibStreamMeta *smeta = (GstQuicLibStreamMeta *) meta, *dmeta;

  /* Always copy */
  dmeta = gst_buffer_add_quiclib_stream_meta (transbuf, smeta->stream_id,
      smeta->stream_type,
      smeta->offset, smeta->length,
      smeta->final);
  if (!dmeta)
    return FALSE;

  return TRUE;
}

static void
quiclib_stream_meta_free (GstMeta *meta, GstBuffer *buffer)
{
  /* Nothing to free */
}

#define MAX_VARINT 0x3FFFFFFFFFFFFFFF

const GstMetaInfo *
gst_quiclib_stream_meta_get_info (void)
{
  static const GstMetaInfo *meta_info = NULL;

  if (g_once_init_enter ((GstMetaInfo **) &meta_info)) {
    const GstMetaInfo *mi = gst_meta_register (
        GST_QUICLIB_STREAM_META_API_TYPE,
        "GstQuicLibStreamMeta", sizeof (GstQuicLibStreamMeta),
        quiclib_stream_meta_init,
        quiclib_stream_meta_free,
        quiclib_stream_meta_transform);
    g_once_init_leave ((GstMetaInfo **) &meta_info, (GstMetaInfo *) mi);
  }

  return meta_info;
}

GstQuicLibStreamMeta *
gst_buffer_add_quiclib_stream_meta (GstBuffer *buffer, gint64 stream_id,
    gint64 stream_type, guint64 offset,
    guint64 length, gboolean final)
{
  GstQuicLibStreamMeta *meta;

  g_return_val_if_fail (GST_IS_BUFFER (buffer), NULL);
  g_return_val_if_fail (stream_id >= 0, NULL);
  g_return_val_if_fail (stream_id <= MAX_VARINT, NULL);
  g_return_val_if_fail (offset < MAX_VARINT, NULL);
  g_return_val_if_fail (length < MAX_VARINT, NULL);
  g_return_val_if_fail (offset + length < MAX_VARINT, NULL);

  meta = (GstQuicLibStreamMeta *) gst_buffer_add_meta (buffer,
      GST_QUICLIB_STREAM_META_INFO, NULL);

  g_return_val_if_fail (meta, NULL);

  meta->stream_id = stream_id;
  meta->stream_type = stream_type;
  meta->offset = offset;
  meta->length = length;
  meta->final = final;

  return meta;
}

GstQuicLibStreamMeta *
gst_buffer_get_quiclib_stream_meta (GstBuffer *buffer) {
  return (GstQuicLibStreamMeta *) gst_buffer_get_meta (buffer,
      GST_QUICLIB_STREAM_META_API_TYPE);
}

guint64
gst_buffer_get_quiclib_stream_meta_id (GstBuffer *buffer) {
  return gst_buffer_get_quiclib_stream_meta (buffer)->stream_id;
}

#define QUIC_ASSOCIATED_STREAM "quic-assoc-stream"

GstQuery *
gst_query_new_get_associated_stream_id (GstPad *local_pad)
{
  GstQuery *query;
  GstStructure *s;

  s = gst_structure_new (QUIC_ASSOCIATED_STREAM, "pad", GST_TYPE_PAD,
      local_pad, NULL);

  query = gst_query_new_custom (GST_QUERY_CUSTOM, s);

  return query;
}

gboolean
gst_query_is_associated_stream_id (GstQuery *query)
{
  const GstStructure *s = gst_query_get_structure (query);

  g_return_val_if_fail (s, FALSE);

  return gst_structure_has_name (s, QUIC_ASSOCIATED_STREAM);
}

GstPad *
gst_query_get_associated_stream_id_pad (GstQuery *query, GstElement *local)
{
  const GstStructure *s;
  GstPad *query_pad, *rv;

  s = gst_query_get_structure (query);

  g_return_val_if_fail (s, NULL);
  g_return_val_if_fail (gst_structure_has_name (s, QUIC_ASSOCIATED_STREAM),
      NULL);

  g_return_val_if_fail (
      gst_structure_get (s, "pad", GST_TYPE_PAD, &query_pad, NULL), NULL);

  if (GST_PAD_PARENT (query_pad) == local) {
    return query_pad;
  }

  rv = gst_pad_get_peer (query_pad);

  if (GST_PAD_PARENT (rv) == local) {
    return rv;
  }

  gst_object_unref (rv);
  return NULL;
}

gboolean
gst_query_fill_get_associated_stream_id (GstQuery *query, guint64 stream_id)
{
  GstStructure *s;

  g_return_val_if_fail (query, FALSE);

  s = gst_query_writable_structure (query);

  g_return_val_if_fail (s != NULL, FALSE);

  g_return_val_if_fail (gst_structure_has_name (s, QUIC_ASSOCIATED_STREAM),
      FALSE);

  gst_structure_set (s, QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id, NULL);

  return TRUE;
}

gboolean
gst_query_parse_get_associated_stream_id (GstQuery *query, guint64 *stream_id)
{
  const GstStructure *s;

  s = gst_query_get_structure (query);

  g_return_val_if_fail (s, FALSE);

  g_return_val_if_fail (
      gst_structure_get_uint64 (s, QUICLIB_STREAMID_KEY, stream_id), FALSE);

  return TRUE;
}


#define QUIC_ASSOCIATED_PAD "quic-assoc-pad"

GstQuery *
gst_query_new_get_associated_pad (guint64 stream_id)
{
  GstQuery *query;
  GstStructure *s;

  s = gst_structure_new (QUIC_ASSOCIATED_PAD,
      QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id, NULL);

  query = gst_query_new_custom (GST_QUERY_CUSTOM, s);

  return query;
}

gboolean
gst_query_is_associated_pad (GstQuery *query)
{
  const GstStructure *s = gst_query_get_structure (query);

  g_return_val_if_fail (s, FALSE);

  return gst_structure_has_name (s, QUIC_ASSOCIATED_PAD);
}

guint64
gst_query_get_associated_pad_stream_id (GstQuery *query)
{
  const GstStructure *s;
  guint64 rv;

  g_return_val_if_fail (query, G_MAXUINT64);

  s = gst_query_get_structure (query);

  g_return_val_if_fail (s, G_MAXUINT64);

  g_return_val_if_fail (gst_structure_get_uint64 (s, QUICLIB_STREAMID_KEY, &rv),
      FALSE);

  return rv;
}

gboolean
gst_query_fill_get_associated_pad (GstQuery *query, GstPad *pad)
{
  GstStructure *s;

  g_return_val_if_fail (query, FALSE);

  s = gst_query_writable_structure (query);

  g_return_val_if_fail (s != NULL, FALSE);

  g_return_val_if_fail (gst_structure_has_name (s, QUIC_ASSOCIATED_PAD), FALSE);

  gst_structure_set (s, "pad", GST_TYPE_PAD, pad, NULL);

  return TRUE;
}

gboolean
gst_query_parse_get_associated_pad (GstQuery *query, GstPad **pad)
{
  const GstStructure *s;

  s = gst_query_get_structure (query);

  g_return_val_if_fail (s, FALSE);

  g_return_val_if_fail (gst_structure_get (s, "pad", GST_TYPE_PAD, pad, NULL),
      FALSE);

  return TRUE;
}
