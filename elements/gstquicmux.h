/*
 * Copyright 2023 British Broadcasting Corporation - Research and Development
 *
 * Author: Sam Hurst <sam.hurst@bbc.co.uk>
 *
 * Based on the GStreamer template repository:
 *  https://gitlab.freedesktop.org/gstreamer/gst-template
 * Copyright (C) 2005 Thomas Vander Stichele <thomas@apestaart.org>
 * Copyright (C) 2005 Ronald S. Bultje <rbultje@ronald.bitfreak.net>
 * Copyright (C) 2020 Niels De Graef <niels.degraef@gmail.com>
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

#ifndef __GST_QUICMUX_H__
#define __GST_QUICMUX_H__

#include <gst/gst.h>

G_BEGIN_DECLS

#define GST_TYPE_QUICMUX_STREAM_OBJECT (gst_quic_mux_stream_object_get_type())
G_DECLARE_FINAL_TYPE (GstQuicMuxStreamObject, gst_quic_mux_stream_object,
    GST, QUICMUX_STREAM_OBJECT, GstObject)

struct _GstQuicMuxStreamObject
{
  GstObject parent;

  GstPad *sinkpad;
  guint64 stream_id;
  guint64 offset;

  GMutex mutex;
  GCond wait;
};

#define GST_TYPE_QUICMUX (gst_quic_mux_get_type())
G_DECLARE_FINAL_TYPE (GstQuicMux, gst_quic_mux,
    GST, QUICMUX, GstElement)

struct _GstQuicMux
{
  GstElement element;

  GRecMutex mutex;

  GstPad *srcpad;
  /*
   * GHashTable <GstPad, GstQuicMuxStreamObject>
   */
  GHashTable *pad_to_stream;
  /*
   * GHashTable <guint64 *, GstQuicMuxStreamObject>
   */
  GHashTable *id_to_stream;

  GList *stream_open_requests;

  gboolean start_stream;
};

G_END_DECLS

#endif /* __GST_QUICMUX_H__ */
