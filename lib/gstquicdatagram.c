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

/**
 * This file includes the declaration of the GstQuicLibDatagramMeta type.
 */

#include "gstquicdatagram.h"

GType
gst_quiclib_datagram_meta_api_get_type (void)
{
    static gsize g_type = 0;
    static const gchar *tags[] = { NULL };

    if (g_once_init_enter (&g_type)) {
        const GType type = gst_meta_api_type_register (
            "GstQuicLibDatagramMetaAPI", tags);
        g_once_init_leave (&g_type, type);
    }

    return g_type;
}

static gboolean
quiclib_datagram_meta_init (GstMeta *meta, gpointer params, GstBuffer *buffer)
{
    GstQuicLibDatagramMeta *datagrammeta = (GstQuicLibDatagramMeta *) meta;

    datagrammeta->length = 0;

    return TRUE;
}

static gboolean
quiclib_datagram_meta_transform (GstBuffer *transbuf, GstMeta *meta,
                               GstBuffer *buffer, GQuark type, gpointer data)
{
    GstQuicLibDatagramMeta *smeta = (GstQuicLibDatagramMeta *) meta, *dmeta;

    /* Always copy */
    dmeta = gst_buffer_add_quiclib_datagram_meta (transbuf, smeta->length);
    if (!dmeta)
        return FALSE;

    return TRUE;
}

static void
quiclib_datagram_meta_free (GstMeta *meta, GstBuffer *buffer)
{
    /* Nothing to free */
}

#define MAX_VARINT 0x3FFFFFFFFFFFFFFF

const GstMetaInfo *
gst_quiclib_datagram_meta_get_info (void)
{
    static const GstMetaInfo *meta_info = NULL;

    if (g_once_init_enter ((GstMetaInfo **) &meta_info)) {
        const GstMetaInfo *mi = gst_meta_register (
                GST_QUICLIB_DATAGRAM_META_API_TYPE,
                "GstQuicLibDatagramMeta", sizeof (GstQuicLibDatagramMeta),
                quiclib_datagram_meta_init,
                quiclib_datagram_meta_free,
                quiclib_datagram_meta_transform);
        g_once_init_leave ((GstMetaInfo **) &meta_info, (GstMetaInfo *) mi);
    }

    return meta_info;
}

GstQuicLibDatagramMeta *
gst_buffer_add_quiclib_datagram_meta (GstBuffer *buffer, guint64 length)
{
    GstQuicLibDatagramMeta *meta;

    g_return_val_if_fail (GST_IS_BUFFER (buffer), NULL);
    g_return_val_if_fail (length <= MAX_VARINT, NULL);

    meta = (GstQuicLibDatagramMeta *) gst_buffer_add_meta (buffer,
            GST_QUICLIB_DATAGRAM_META_INFO, NULL);

    g_return_val_if_fail (meta, NULL);

    meta->length = length;

    return meta;
}

GstQuicLibDatagramMeta *
gst_buffer_get_quiclib_datagram_meta (GstBuffer *buffer) {
    return (GstQuicLibDatagramMeta *) gst_buffer_get_meta (buffer,
            GST_QUICLIB_DATAGRAM_META_API_TYPE);
}
