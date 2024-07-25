/*
 * Copyright 2024 British Broadcasting Corporation - Research and Development
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

#include "gstquicpriv.h"

#include <gio/gresolver.h>
#include <gio/gunixsocketaddress.h>

GUri *
gst_quiclib_parse_location (const gchar *location)
{
  GError *err = NULL;
  GUri *uri = g_uri_parse (location, G_URI_FLAGS_NONE, &err);

  if (uri == NULL) {
    g_warning ("Failed to parse location \"%s\" to URI: %s", location,
        err->message);
    g_error_free (err);
    return NULL;
  }

  /* Make sure that the default port is 443 if nothing else was specified. */
  if (g_uri_get_port (uri) == -1) {
    /* GUri doesn't have a set_port function for some reason... */
    GUri *default_port_uri = g_uri_build (G_URI_FLAGS_NONE,
        g_strdup (g_uri_get_scheme (uri)),
        g_strdup (g_uri_get_userinfo (uri)),
        g_strdup (g_uri_get_host (uri)),
        443,
        g_strdup (g_uri_get_path (uri)),
        g_strdup (g_uri_get_query (uri)),
        g_strdup (g_uri_get_fragment (uri)));
    g_uri_unref (uri);
    uri = default_port_uri;
  }

  return uri;
}

GInetSocketAddress *
gst_quiclib_resolve (GUri *uri)
{
  GResolver *resolver;
  GError *err = NULL;
  GList *addrs, *it = NULL;
  GInetAddress *addr = NULL;
  GInetSocketAddress *rv;

  resolver = g_resolver_get_default ();

  addrs = g_resolver_lookup_by_name (resolver, g_uri_get_host (uri), NULL,
      &err);
  if (addrs == NULL) {
    g_warning ("Failed to resolve host \"%s\": %s", g_uri_get_host (uri),
        err->message);
    g_error_free (err);
    g_object_unref (resolver);
    return NULL;
  }

  it = addrs;

  while (it != NULL) {
    GInetAddress *a = (GInetAddress *) it->data;
    if ((g_inet_address_get_family (a) == G_SOCKET_FAMILY_IPV4) ||
        (g_inet_address_get_family (a) == G_SOCKET_FAMILY_IPV6)) {
      addr = a;
      break;
    }
  }

  rv = (GInetSocketAddress * ) g_inet_socket_address_new (addr,
      g_uri_get_port (uri));

  g_list_free_full (addrs, g_object_unref);

  g_object_unref (resolver);

  return rv;
}
