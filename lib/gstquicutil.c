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

#include "gstquicutil.h"

#include <arpa/inet.h> /* for htons */

#define _VARLEN_INT_MAX_62_BIT 0x4000000000000000ULL
#define _VARLEN_INT_MAX_30_BIT 0x40000000
#define _VARLEN_INT_MAX_14_BIT 0x4000
#define _VARLEN_INT_MAX_6_BIT 0x40

#define _VARLEN_INT_62_BIT 0xC0
#define _VARLEN_INT_30_BIT 0x80
#define _VARLEN_INT_14_BIT 0x40
#define _VARLEN_INT_6_BIT 0x00
#define _VARLEN_MASK_CLEAR 0x3f

#ifdef WORDS_BIGENDIAN
#define bswap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#define bswap64(N) \
  ((guint64)(ntohl((guint32)(N))) << 32 | ntohl((guint32)((N) >> 32)))
#endif /* !WORDS_BIGENDIAN */

void
quiclib_put_uint16_in_buf (guint8 *buf, guint16 n)
{
  n = htons (n);
  memcpy (buf, (guint8 *) &n, 2);
}

void
quiclib_put_uint32_in_buf (guint8 *buf, guint32 n)
{
  n = htonl (n);
  memcpy (buf, (guint8 *) &n, 4);
}

void
quiclib_put_uint64_in_buf (guint8 *buf, guint64 n)
{
  n = bswap64 (n);
  memcpy (buf, (guint8 *) &n, 8);
}

gsize
gst_quiclib_get_varint (const guint8 *buf, guint64 *var)
{
  guint64 rv = 0;
  union {
    guint8 b[8];
    guint16 n16;
    guint32 n32;
    guint64 n64;
  } n;

  switch (buf[0] & _VARLEN_INT_62_BIT) {
  case _VARLEN_INT_6_BIT:
    rv = 1;
    *var = (guint64) buf[0];
    break;
  case _VARLEN_INT_14_BIT:
    rv = 2;
    memcpy (&n, buf, 2);
    n.b[0] &= _VARLEN_MASK_CLEAR;
    *var = (guint64) ntohs (n.n16);
    break;
  case _VARLEN_INT_30_BIT:
    rv = 4;
    memcpy (&n, buf, 4);
    n.b[0] &= _VARLEN_MASK_CLEAR;
    *var = (guint64) ntohl (n.n32);
    break;
  case _VARLEN_INT_62_BIT:
    rv = 8;
    memcpy (&n, buf, 8);
    n.b[0] &= _VARLEN_MASK_CLEAR;
    *var = (guint64) bswap64 (n.n64);
    break;
  }

  return rv;
}

gsize
gst_quiclib_set_varint (guint64 var, guint8 *buf)
{
  gsize rv = 0; /* Returns 0 if var >62 bits */
  if (var < _VARLEN_INT_MAX_6_BIT) {
    if (buf != NULL) {
      buf[0] = (guint8) var;
    }
    rv = 1;
  } else if (var < _VARLEN_INT_MAX_14_BIT) {
    if (buf != NULL) {
      quiclib_put_uint16_in_buf (buf, (guint16) var);
      buf[0] |= _VARLEN_INT_14_BIT;
    }
    rv = 2;
  } else if (var < _VARLEN_INT_MAX_30_BIT) {
    if (buf != NULL) {
      quiclib_put_uint32_in_buf (buf, (guint32) var);
      buf[0] |= _VARLEN_INT_30_BIT;
    }
    rv = 4;
  } else if (var < _VARLEN_INT_MAX_62_BIT) {
    if (buf != NULL) {
      quiclib_put_uint64_in_buf (buf, var);
      buf[0] |= _VARLEN_INT_62_BIT;
    }
    rv = 8;
  }
  return rv;
}
