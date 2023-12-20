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

#ifndef LIB_GSTQUICUTIL_H_
#define LIB_GSTQUICUTIL_H_

#include <gst/gst.h>

/**
 * Utility functions for QUIC variable-length integers
 */

/*
 * Maximum length of a varint - 2^62 -1
 */
#define QUICLIB_VARINT_MAX 4611686018427387903

/**
 * gst_quiclib_get_varint:
 * @buf a #guint8 buffer of at least eight bytes in length
 * @var a #guint64 variable to return the varint contained in @buf
 *
 * Gets a QUIC variable length integer from a byte buffer
 *
 * Returns: The size of the varint (1, 2, 4, or 8 bytes). Returns <0 on error.
 */
gsize
gst_quiclib_get_varint (const guint8 *buf, guint64 *var);

/**
 * gst_quiclib_set_varint:
 * @var a #guint64 variable that is less than QUICLIB_VARINT_MAX to write
 * @buf The destination buffer that is at least 8 bytes in size.
 *
 * Writes a QUIC variable length integer into a byte buffer
 *
 * Returns: The size of the varint that was written, or <0 on error.
 */
gsize
gst_quiclib_set_varint (guint64 var, guint8 *buf);



#endif /* LIB_GSTQUICUTIL_H_ */
