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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>

#include "gstquiccommon.h"
#include "gstquictransport.h"
#include "gstquicstream.h"

#include <gst/gst.h>
#include <gio/gresolver.h>
#include <gio/gunixsocketaddress.h>

G_DEFINE_BOXED_TYPE (GstQuicLibAddressList, gst_quiclib_address_list,
    gst_quiclib_address_list_copy, gst_quiclib_address_list_free)

GSocketAddress *
_quiclib_copy_address (GSocketAddress *src, gpointer data)
{
  return g_object_ref (src);
  /*switch (g_socket_address_get_family ((GSocketAddress *) src)) {
    case G_SOCKET_FAMILY_UNIX:
      return g_unix_socket_address_new (
          g_unix_socket_address_get_path (G_UNIX_SOCKET_ADDRESS (src)));
    case G_SOCKET_FAMILY_IPV4:
    case G_SOCKET_FAMILY_IPV6:
      return g_inet_socket_address_new (
          g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (src)),
          g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (src)));
    default:
      return NULL;
  }*/
}

GstQuicLibAddressList *
gst_quiclib_address_list_copy (GstQuicLibAddressList *list)
{
  GList *new = g_list_copy_deep (list, (GCopyFunc) _quiclib_copy_address, NULL);

  return new;
}

void
gst_quiclib_address_list_free (GstQuicLibAddressList *list)
{
  g_list_free_full (list, g_object_unref);
}

typedef struct _QuicLibEndpoint {
  GInetSocketAddress *sa;
  GstQuicLibTransportContext *tcxt;
} QuicLibEndpoint;

typedef struct _QuicLibContext {
  GSList *users;
} QuicLibContext;

/*#define USE_HASHTABLE*/

struct _GstQuicLibCommon {
  GstObject object;

  GResolver *resolver;

#ifdef USE_HASHTABLE
  /*
   * Key = GInetSocketAddress
   * Value = GstQuicLibTransportContext
   */
  GHashTable *client_instances;
  GHashTable *listening_servers;
#else
  GList *clients;
  GList *servers;
#endif

  GMutex mutex;
};

GST_DEBUG_CATEGORY_STATIC (quiclib_common);
#define GST_CAT_DEFAULT quiclib_common

static void
gst_quiclib_common_transport_user_init (gpointer g_iface, gpointer iface_data);

#define gst_quiclib_common_parent_class parent_class
G_DEFINE_TYPE_WITH_CODE (GstQuicLibCommon, gst_quiclib_common, GST_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE (GST_QUICLIB_TRANSPORT_USER,
        gst_quiclib_common_transport_user_init));

static GObject * gst_quiclib_common_constructor (GType type,
    guint n_construct_params, GObjectConstructParam *construct_params);
void gst_quiclib_common_dispose (GObject *obj);

static GUri *
quiclib_parse_location (GstQuicLibCommon *ctx, const gchar *location)
{
  GError *err = NULL;
  GUri *uri = g_uri_parse (location, G_URI_FLAGS_NONE, &err);

  if (uri == NULL) {
    GST_ERROR_OBJECT (ctx, "Failed to parse location \"%s\" to URI: %s",
        location, err->message);
    g_free (err);
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

static GInetSocketAddress *
quiclib_resolve (GstQuicLibCommon *ctx, GUri *uri)
{
  GError *err = NULL;
  GList *addrs, *it = NULL;
  GInetAddress *addr = NULL;
  GInetSocketAddress *rv;

  if (ctx->resolver == NULL) {
    ctx->resolver = g_resolver_get_default ();
  }

  addrs = g_resolver_lookup_by_name (ctx->resolver, g_uri_get_host (uri), NULL,
      &err);
  if (addrs == NULL) {
    GST_ERROR_OBJECT (ctx, "Failed to resolve host \"%s\": %s",
        g_uri_get_host (uri), err->message);
    g_free (err);
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

  return rv;
}

#ifdef USE_HASHTABLE
static guint
quiclib_client_endpoint_hash (gconstpointer key)
{
  GstQuicLibTransportConnection *ctx =
      GST_QUICLIB_TRANSPORT_CONNECTION ((gpointer) key);
  GInetSocketAddress *sa = gst_quiclib_transport_get_peer (ctx);
  guint hash;

  g_return_val_if_fail (sa, 0);

  switch (g_socket_address_get_family (G_SOCKET_ADDRESS (sa))) {
  case G_SOCKET_FAMILY_IPV4:
  case G_SOCKET_FAMILY_IPV6:
  {
    GInetAddress *ia = g_inet_socket_address_get_address (sa);
    GBytes *bytes = g_bytes_new (g_inet_address_to_bytes (ia),
        g_inet_address_get_native_size (ia));
    hash = g_bytes_hash (bytes);
    g_bytes_unref (bytes);
    break;
  }
  default:
    abort();
  }

  g_object_unref (sa);

  return hash;
}

static guint
quiclib_server_endpoint_hash (gconstpointer key)
{
  GstQuicLibServerContext *ctx = GST_QUICLIB_SERVER_CONTEXT ((gpointer) key);
  GSList *a, *addrs = gst_quiclib_transport_get_listening_addrs (ctx);
  GByteArray *ba;
  GBytes *bytes;
  guint n = 0, hash;
  gsize buflen = 0;

  g_return_val_if_fail (addrs, 0);

  a = addrs;

  while (addrs != NULL) {
    if ((g_socket_address_get_family ((GSocketAddress *) addrs->data)
            != G_SOCKET_FAMILY_IPV4) &&
        (g_socket_address_get_family ((GSocketAddress *) addrs->data)
            != G_SOCKET_FAMILY_IPV6)) {
      abort();
    }
    buflen += g_inet_address_get_native_size (
        g_inet_socket_address_get_address (
            (GInetSocketAddress *) addrs->data));
    n++;
    addrs = addrs->next;
  }

  ba = g_byte_array_sized_new (buflen + ((n - 1) * 2));
  addrs = a;

  while (addrs != NULL) {
    GInetAddress *ia =
        g_inet_socket_address_get_address ((GInetSocketAddress *) addrs->data);
    ba = g_byte_array_append (ba, g_inet_address_to_bytes (ia),
        g_inet_address_get_native_size (ia));
    addrs = addrs->next;
  }

  bytes = g_byte_array_free_to_bytes (ba);
  hash = g_bytes_hash (bytes);
  g_bytes_unref (bytes);

  return hash;
}

/* GEqualFunc implementation */
static gboolean
quiclib_endpoint_equal (gconstpointer pa, gconstpointer pb)
{
  GInetSocketAddress *a = (GInetSocketAddress *) pa;
  GInetSocketAddress *b = (GInetSocketAddress *) pb;

  if (g_socket_address_get_family ((GSocketAddress *) a) !=
      g_socket_address_get_family ((GSocketAddress *) b))
  {
    return FALSE;
  }

  if (g_inet_socket_address_get_port (a) != g_inet_socket_address_get_port (b))
  {
    return FALSE;
  }

  return g_inet_address_equal (g_inet_socket_address_get_address (a),
      g_inet_socket_address_get_address (b));
}

static GstQuicLibTransportContext *
quiclib_get_instance (GHashTable *t, GInetSocketAddress *addr)
{
  GstQuicLibTransportContext *rv;

  if (g_hash_table_lookup_extended (t, addr, NULL, (gpointer *) &rv)) {
    return rv;
  }

  /* Nothing matches in the hash table, so time to create a new one */
  return NULL;
}
#endif

static void
gst_quiclib_common_class_init (GstQuicLibCommonClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->constructor = gst_quiclib_common_constructor;
  object_class->dispose = gst_quiclib_common_dispose;

  GST_DEBUG_CATEGORY_INIT (quiclib_common, "quiccommon", 0,
        "Singleton class for managing QUIC Transport connections");
}

static void
gst_quiclib_common_init (GstQuicLibCommon *self)
{
#ifdef USE_HASHTABLE
  self->client_instances =
      g_hash_table_new (quiclib_client_endpoint_hash, quiclib_endpoint_equal);
  self->listening_servers =
      g_hash_table_new (quiclib_server_endpoint_hash, quiclib_endpoint_equal);
#else
  self->clients = self->servers = NULL;
#endif

  g_mutex_init (&self->mutex);
}

static GObject *
gst_quiclib_common_constructor (GType type, guint n_construct_params,
    GObjectConstructParam *construct_params)
{
  /*
   * Adapted from here:
   * https://blogs.gnome.org/xclaesse/2010/02/11/how-to-make-a-gobject-singleton/
   */
  static GObject *self = NULL;

  /* TODO: Make thread safe */
  if (self == NULL) {
    self =
        G_OBJECT_CLASS (gst_quiclib_common_parent_class)->constructor (
        type, n_construct_params, construct_params);
    g_object_add_weak_pointer (self, (gpointer) &self);
    return self;
  }

  return g_object_ref (self);
}

void
quiclib_foreach_close_conn (GstQuicLibTransportConnection *conn,
    GstQuicLibCommon *common)
{
  g_assert (GST_IS_QUICLIB_TRANSPORT_CONNECTION (conn));

  gst_quiclib_transport_disconnect (conn, FALSE, QUICLIB_CLOSE_NO_ERROR);

  gst_object_unref (conn);
}

void
quiclib_foreach_stop_server (GstQuicLibServerContext *server,
    GstQuicLibCommon *common)
{
  g_assert (GST_IS_QUICLIB_SERVER_CONTEXT (server));

  if (gst_quiclib_transport_server_remove_listens (server, NULL)) {
    gst_object_unref (server);
  }
}

void
gst_quiclib_common_dispose (GObject *obj)
{
  GstQuicLibCommon *self = GST_QUICLIB_COMMON (obj);

#ifdef USE_HASHTABLE
  g_hash_table_unref (self->client_instances);
  g_hash_table_unref (self->listening_servers);
#else
  g_list_foreach (self->clients, (GFunc) quiclib_foreach_close_conn, self);
  g_list_foreach (self->servers, (GFunc) quiclib_foreach_stop_server, self);
#endif

  g_object_unref (self->resolver);

  G_OBJECT_CLASS(gst_quiclib_common_parent_class)->dispose(obj);
}

static gboolean
quiclib_common_transport_new_connection (GstQuicLibTransportUser *self,
    GstQuicLibTransportContext *ctx, GInetSocketAddress *remote,
    const gchar *alpn)
{
  GList *users = (GList *) gst_quiclib_transport_get_app_ctx (ctx);

  for (; users != NULL; users = g_list_next (users)) {
    GstQuicLibCommonUser *user = (GstQuicLibCommonUser *) users->data;
    GstQuicLibCommonUserInterface *iface =
        GST_QUICLIB_COMMON_USER_GET_IFACE (user);
    if (iface->new_connection != NULL &&
        !iface->new_connection (user, ctx, remote, alpn)) {
      return FALSE;
    }
  }

  return TRUE;
}

static gboolean
quiclib_common_transport_handshake_complete (GstQuicLibTransportUser *self,
    GstQuicLibTransportContext *ctx, GstQuicLibTransportConnection *conn,
    GInetSocketAddress *remote, const gchar *alpn)
{
  GList *users = (GList *) gst_quiclib_transport_get_app_ctx (ctx);

  for (; users != NULL; users = g_list_next (users)) {
    GstQuicLibCommonUser *user = (GstQuicLibCommonUser *) users->data;
    GstQuicLibCommonUserInterface *iface =
        GST_QUICLIB_COMMON_USER_GET_IFACE (user);
    if (iface->handshake_complete != NULL &&
        !iface->handshake_complete (user, ctx, remote, alpn, conn)) {
      return FALSE;
    }
  }

  return TRUE;
}

static gboolean
quiclib_common_transport_stream_opened (GstQuicLibTransportUser *self,
    GstQuicLibTransportContext *ctx, guint64 stream_id)
{
  GList *users = (GList *) gst_quiclib_transport_get_app_ctx (ctx);

  for (; users != NULL; users = g_list_next (users)) {
    GstQuicLibCommonUser *user = (GstQuicLibCommonUser *) users->data;
    GstQuicLibCommonUserInterface *iface =
        GST_QUICLIB_COMMON_USER_GET_IFACE (user);
    if (iface->stream_opened != NULL &&
        !iface->stream_opened (user, ctx, stream_id)) {
      return FALSE;
    }
  }

  return TRUE;
}

static void
quiclib_common_transport_stream_closed (GstQuicLibTransportUser *self,
    GstQuicLibTransportContext *ctx, guint64 stream_id)
{
  GList *users = (GList *) gst_quiclib_transport_get_app_ctx (ctx);

  for (; users != NULL; users = g_list_next (users)) {
    GstQuicLibCommonUser *user = (GstQuicLibCommonUser *) users->data;
    GstQuicLibCommonUserInterface *iface =
        GST_QUICLIB_COMMON_USER_GET_IFACE (user);
    if (iface->stream_closed != NULL) {
      iface->stream_closed (user, ctx, stream_id);
    }
  }
}

static void
quiclib_common_transport_stream_data (GstQuicLibTransportUser *self,
    GstQuicLibTransportContext *ctx, GstBuffer *buf)
{
  GList *users = (GList *) gst_quiclib_transport_get_app_ctx (ctx);

  for (; users != NULL; users = g_list_next (users)) {
    GstQuicLibCommonUser *user = (GstQuicLibCommonUser *) users->data;
    GstQuicLibCommonUserInterface *iface =
        GST_QUICLIB_COMMON_USER_GET_IFACE (user);
    if (iface->stream_data != NULL) {
      iface->stream_data (user, ctx, buf);
    }
  }
}

static void
quiclib_common_transport_stream_ackd (GstQuicLibTransportUser *self,
    GstQuicLibTransportContext *ctx, guint64 stream_id, gsize ackd_offset,
    GstBuffer *ackd_buffer)
{
  GList *users = (GList *) gst_quiclib_transport_get_app_ctx (ctx);

  for (; users != NULL; users = g_list_next (users)) {
    GstQuicLibCommonUser *user = (GstQuicLibCommonUser *) users->data;
    GstQuicLibCommonUserInterface *iface =
        GST_QUICLIB_COMMON_USER_GET_IFACE (user);
    if (iface->stream_ackd != NULL) {
      iface->stream_ackd (user, ctx, stream_id, ackd_offset);
    }
  }
}

static void
quiclib_common_transport_datagram_ackd (GstQuicLibTransportUser *self,
    GstQuicLibTransportContext *ctx, GstBuffer *ackd_datagram)
{
  GList *users = (GList *) gst_quiclib_transport_get_app_ctx (ctx);

  for (; users != NULL; users = g_list_next (users)) {
    GstQuicLibCommonUser *user = (GstQuicLibCommonUser *) users->data;
    GstQuicLibCommonUserInterface *iface =
        GST_QUICLIB_COMMON_USER_GET_IFACE (user);
    if (iface->datagram_ackd != NULL) {
      iface->datagram_ackd (user, ctx, ackd_datagram);
    }
  }
}

static gboolean
quiclib_common_transport_connection_error (GstQuicLibTransportUser *self,
    GstQuicLibTransportContext *ctx, guint64 error)
{
  gboolean ret = FALSE;
  GList *users = (GList *) gst_quiclib_transport_get_app_ctx (ctx);

  for (; users != NULL; users = g_list_next (users)) {
    GstQuicLibCommonUser *user = (GstQuicLibCommonUser *) users->data;
    GstQuicLibCommonUserInterface *iface =
        GST_QUICLIB_COMMON_USER_GET_IFACE (user);
    if (iface->connection_error != NULL &&
        iface->connection_error (user, ctx, error)) {
      ret = TRUE;
    }
  }

  return ret;
}

static void
quiclib_common_transport_connection_closed (GstQuicLibTransportUser *self,
    GstQuicLibTransportContext *ctx, GInetSocketAddress *remote)
{
  GList *users = (GList *) gst_quiclib_transport_get_app_ctx (ctx);

  for (; users != NULL; users = g_list_next (users)) {
    GstQuicLibCommonUser *user = (GstQuicLibCommonUser *) users->data;
    GstQuicLibCommonUserInterface *iface =
        GST_QUICLIB_COMMON_USER_GET_IFACE (user);
    if (iface->connection_closed != NULL) {
      iface->connection_closed (user, ctx, remote);
    }
  }
}

gboolean
quiclib_sockaddr_equals (GSocketAddress *a, GSocketAddress *b)
{
  if (g_socket_address_get_family (a) != g_socket_address_get_family (b)) {
    return FALSE;
  }

  switch (g_socket_address_get_family (a)) {
  case G_SOCKET_FAMILY_IPV4:
  case G_SOCKET_FAMILY_IPV6:
    break;
  default:
    g_return_val_if_reached (FALSE);
  }

  return g_inet_address_equal (
      g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (a)),
      g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (b)));
}

GSList *
quiclib_alpns_to_list (gchar *alpns)
{
  GSList *list = NULL;

  gchar *start = (gchar *) alpns, *end = NULL;

  while (start != NULL && *start != '\0') {
    gchar *alpn;

    end = strchrnul (start, ',');

    alpn = g_malloc ((end - start) + 1);
    if (!alpn) break;

    strncpy (alpn, start, end - start);
    alpn [end - start] = 0;

    list = g_slist_append (list, alpn);

    start = end + 1;

    while (*start == ',' || *start == ' ') {
      start++;
    }
  }

  return list;
}

GstQuicLibServerContext *
gst_quiclib_listen (GstQuicLibCommonUser *user, const gchar *location,
    const gchar *alpns, const gchar *privkey_location,
    const gchar *cert_location, const gchar *sni)
{
  GUri *uri;
  GInetSocketAddress *sa;
  GstQuicLibServerContext *server = NULL;
  GstQuicLibCommon *libctx =
      (GstQuicLibCommon *) g_object_new (GST_TYPE_QUICLIB_COMMON, NULL);
  GSList *addrs = NULL;
  GSList *alpn_list = NULL;
  GList *users = libctx->servers;
  gchar alpn_str[strnlen (alpns, 255)];

  uri = quiclib_parse_location (libctx, location);
  if (!uri) {
    goto free_libctx;
  }

  sa = quiclib_resolve (libctx, uri);
  if (!sa) {
    goto free_uri;
  }

  strncpy (alpn_str, alpns, strnlen (alpns, 255));
  alpn_str[strnlen (alpns, 255)] = 0;
  alpn_list = quiclib_alpns_to_list (alpn_str);

  while (users != NULL) {
    GSList *addrs = gst_quiclib_transport_get_listening_addrs (
        GST_QUICLIB_SERVER_CONTEXT (users->data));
    while (addrs != NULL) {
      if (quiclib_sockaddr_equals (G_SOCKET_ADDRESS (sa),
          G_SOCKET_ADDRESS (addrs->data))) {
        server = GST_QUICLIB_SERVER_CONTEXT (users->data);
        break;
      }

      addrs = addrs->next;
    }
    users = users->next;
  }

  if (!server) {
    addrs = g_slist_append (addrs, sa);
    users = g_list_append (users, user);
    server = gst_quiclib_transport_server_listen (
        QUICLIB_TRANSPORT_USER (libctx), addrs, privkey_location,
        cert_location, sni, alpn_list, users);
    libctx->servers = g_list_append (libctx->servers, server);
    g_assert (libctx->servers);
  } else {
    /*
     * Check that the list of ALPNs is compatible with the existing. If there's
     * any that don't match, return an error because otherwise we might not be
     * supporting something critical.
     */
    GSList *alpn_it = alpn_list;

    while (alpn_it != NULL) {
      GSList *existing = gst_quiclib_transport_get_acceptable_alpns (server);

      while (existing != NULL) {
        if (strcmp ((gchar *) alpn_it->data, (gchar *) existing->data) == 0) {
          break;
        }
        existing = existing->next;
      }

      if (existing == NULL) {
        GST_WARNING_OBJECT (libctx,
            "New ALPN \"%s\" wasn't compatible with existing server instance",
            (gchar *) alpn_it->data);
        return NULL;
      }

      alpn_it = alpn_it->next;
    }

    users = (GList *) gst_quiclib_transport_get_app_ctx (
        GST_QUICLIB_TRANSPORT_CONTEXT (server));
    users = g_list_append (users, user);
  }

  return server;

free_uri:
  g_object_unref (uri);
free_libctx:
  g_object_unref (libctx);
  return NULL;
}

GstQuicLibTransportConnection *
gst_quiclib_connect (GstQuicLibCommonUser *user, const gchar *location,
                     const gchar *alpn)
{
  GUri *uri;
  GInetSocketAddress *sa;
  GstQuicLibTransportConnection *conn = NULL;
  GstQuicLibCommon *libctx = (GstQuicLibCommon *)
      g_object_new (GST_TYPE_QUICLIB_COMMON, NULL);
  GList *connections = libctx->clients;

  uri = quiclib_parse_location (libctx, location);
  if (!uri) {
    goto free_libctx;
  }

  sa = quiclib_resolve (libctx, uri);
  if (!sa) {
    goto free_uri;
  }

  while (connections != NULL) {
    GSocketAddress *peer = G_SOCKET_ADDRESS (gst_quiclib_transport_get_peer (
        GST_QUICLIB_TRANSPORT_CONNECTION (connections->data)));
    if (quiclib_sockaddr_equals (G_SOCKET_ADDRESS (sa),
        G_SOCKET_ADDRESS (peer))) {
      conn = GST_QUICLIB_TRANSPORT_CONNECTION (connections->data);
      break;
    }
    connections = connections->next;
  }

  if (!conn) {
    connections = g_list_append (connections, user);
    conn = gst_quiclib_transport_client_connect (
        QUICLIB_TRANSPORT_USER (libctx), sa, g_uri_get_host (uri), alpn,
        connections);
    libctx->clients = g_list_append (libctx->clients, conn);
    g_assert (libctx->clients);
  } else {
    connections = (GList *) gst_quiclib_transport_get_app_ctx (
        GST_QUICLIB_TRANSPORT_CONTEXT (conn));
    connections = g_list_append (connections, user);
  }

  return conn;

free_uri:
  g_object_unref (uri);
free_libctx:
  g_object_unref (libctx);
  return NULL;
}

GInetSocketAddress *
gst_quiclib_get_connection_peer (GstQuicLibTransportContext *ctx)
{
  if (gst_quiclib_transport_get_mode (ctx) == QUICLIB_MODE_SERVER) {
    return NULL;
  }

  return gst_quiclib_transport_get_peer (
      GST_QUICLIB_TRANSPORT_CONNECTION (ctx));
}

void
gst_quiclib_unref (GstQuicLibTransportContext *ctx,
    GstQuicLibCommonUser *user)
{
  GstQuicLibCommon *libctx = (GstQuicLibCommon *)
      g_object_new (GST_TYPE_QUICLIB_COMMON, NULL);
  GList *users;

  GST_DEBUG_OBJECT (libctx, "Locking mutex!");
  g_mutex_lock (&libctx->mutex);

  users = (GList *) gst_quiclib_transport_get_app_ctx (ctx);

  users = g_list_remove (users, (gconstpointer) user);

  if (g_list_length (users) == 0) {
    /* Emtpy list, destroy */

    if (gst_quiclib_transport_get_mode (ctx) == QUICLIB_MODE_SERVER) {
      libctx->servers = g_list_remove (libctx->servers, (gconstpointer) ctx);
    } else {
      libctx->clients = g_list_remove (libctx->clients, (gconstpointer) ctx);
    }

    g_object_unref (ctx);
  } else {
    /* Just in case this changed the front of the list */
    gst_quiclib_transport_set_app_ctx (ctx, (gpointer) users);
  }

  GST_DEBUG_OBJECT (libctx, "Unlocking mutex!");
  g_mutex_unlock (&libctx->mutex);
}

gboolean
quiclib_new_event (GstPad *pad, GstStructure *structure)
{
  GstEvent *event = NULL;

  switch (gst_pad_get_direction (pad)) {
    case GST_PAD_UNKNOWN:
      g_return_val_if_reached (FALSE);
    case GST_PAD_SRC:
      event = gst_event_new_custom (GST_EVENT_CUSTOM_DOWNSTREAM, structure);
      break;
    case GST_PAD_SINK:
      event = gst_event_new_custom (GST_EVENT_CUSTOM_UPSTREAM, structure);
      break;
  }

  g_return_val_if_fail (event != NULL, FALSE);

  return gst_pad_push_event (pad, event);
}

gboolean
quiclib_new_element_event (GstElement *element, GstStructure *structure)
{
  GstEvent *event = gst_event_new_custom (GST_EVENT_CUSTOM_BOTH, structure);

  g_return_val_if_fail (event != NULL, FALSE);

  return gst_element_send_event (element, event);
}

GstQuery *
gst_query_new_quiclib_client_connect (GSocketAddress *peer, const gchar *alpn)
{
  GstQuery *query;
  GstStructure *s;

  s = gst_structure_new (QUICLIB_CLIENT_CONNECT,
      QUICLIB_CONNECTION_PEER, G_TYPE_SOCKET_ADDRESS, peer,
      QUICLIB_CONNECTION_PROTO, G_TYPE_STRING, alpn, NULL);

  query = gst_query_new_custom (GST_QUERY_CUSTOM, s);

  return query;
}

gboolean
gst_query_parse_quiclib_client_connect (GstQuery *query, GSocketAddress **peer,
    gchar **alpn)
{
  const GstStructure *s;

  s = gst_query_get_structure (query);

  g_return_val_if_fail (s, FALSE);

  return TRUE;
}

gboolean
gst_quiclib_new_handshake_complete_event (GstPad *pad, GSocketAddress *peer,
    const gchar *alpn)
{
  return quiclib_new_event (pad, gst_structure_new (QUICLIB_HANDSHAKE_COMPLETE,
      QUICLIB_CONNECTION_PEER, G_TYPE_SOCKET_ADDRESS, peer,
      QUICLIB_CONNECTION_PROTO, G_TYPE_STRING, alpn, NULL));
}

gboolean
gst_quiclib_parse_handshake_complete_event (GstEvent *event,
    GSocketAddress **peer, gchar **alpn)
{
  const GstStructure *s;

  s = gst_event_get_structure (event);

  g_return_val_if_fail (s, FALSE);

  g_return_val_if_fail (gst_structure_has_name (s, QUICLIB_HANDSHAKE_COMPLETE),
        FALSE);

  if (peer != NULL) {
    const GValue *sa_box =
        gst_structure_get_value (s, QUICLIB_CONNECTION_PEER);

    g_assert (sa_box);

    if (sa_box) {
      *peer = G_SOCKET_ADDRESS (g_value_get_object (sa_box));
    }
  }

  if (alpn != NULL) {
    const gchar *local_alpn = gst_structure_get_string (s,
        QUICLIB_CONNECTION_PROTO);

    g_assert (local_alpn);

    *alpn = g_malloc (strlen (local_alpn) + 1);
    strcpy (*alpn, local_alpn);
  }

  return TRUE;
}

gboolean
gst_quiclib_new_stream_opened_event (GstPad *pad, guint64 stream_id)
{
  return quiclib_new_event (pad, gst_structure_new (QUICLIB_STREAM_OPEN,
      QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id, NULL));
}

gboolean
gst_quiclib_parse_stream_opened_event (GstEvent *event, guint64 *stream_id)
{
  const GstStructure *s;

  s = gst_event_get_structure (event);

  g_return_val_if_fail (s, FALSE);

  g_return_val_if_fail (gst_structure_has_name (s, QUICLIB_STREAM_OPEN),
      FALSE);

  g_return_val_if_fail (gst_structure_get_uint64 (s, QUICLIB_STREAMID_KEY,
      stream_id), FALSE);

  return TRUE;
}

gboolean
gst_quiclib_new_stream_closed_event (GstPad *pad, guint64 stream_id)
{
  return quiclib_new_event (pad, gst_structure_new (QUICLIB_STREAM_CLOSE,
      QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id, NULL));
}

gboolean
gst_quiclib_parse_stream_closed_event (GstEvent *event, guint64 *stream_id)
{
  const GstStructure *s;

  s = gst_event_get_structure (event);

  g_return_val_if_fail (s, FALSE);

  g_return_val_if_fail (gst_structure_has_name (s, QUICLIB_STREAM_CLOSE),
      FALSE);

  g_return_val_if_fail (gst_structure_get_uint64 (s, QUICLIB_STREAMID_KEY,
      stream_id), FALSE);

  return TRUE;
}

gboolean
gst_quiclib_new_connection_error_pad_event (GstPad *pad, guint64 error)
{
  return quiclib_new_event (pad, gst_structure_new (QUICLIB_CONNECTION_CLOSE,
      QUICLIB_CANCEL_REASON, G_TYPE_UINT64, error, NULL));
}

gboolean
gst_quiclib_new_connection_error_element_event (GstElement *element,
    guint64 error)
{
  return quiclib_new_element_event (element, gst_structure_new (
      QUICLIB_CONNECTION_CLOSE, QUICLIB_CANCEL_REASON, G_TYPE_UINT64, error,
      NULL));
}

gboolean
gst_quiclib_parse_connection_error_event (GstEvent *event, guint64 *error)
{
  const GstStructure *s;

  s = gst_event_get_structure (event);

  g_return_val_if_fail (s, FALSE);

  g_return_val_if_fail (gst_structure_has_name (s, QUICLIB_CONNECTION_CLOSE),
      FALSE);

  g_return_val_if_fail (gst_structure_get_uint64 (s, QUICLIB_CANCEL_REASON,
      error), FALSE);

  return TRUE;
}

GstQuicLibStreamType
gst_quiclib_get_stream_type_from_id (guint64 stream_id)
{
  if (stream_id & 0x2) return QUIC_STREAM_UNI;
  return QUIC_STREAM_BIDI;
}

GstQuery *
gst_query_new_quiclib_conn_state ()
{
  GstQuery *query;
  GstStructure *s;

  s = gst_structure_new (QUICLIB_CONNECTION_STATE, NULL, NULL);

  query = gst_query_new_custom (GST_QUERY_CUSTOM, s);

  return query;
}

gboolean
gst_query_fill_quiclib_conn_state (GstQuery *query, GstQUICMode mode,
    GstQuicLibTransportState state, GSocketAddress *local, GSocketAddress *peer)
{
  GstStructure *s;

  g_return_val_if_fail (query, FALSE);

  s = gst_query_writable_structure (query);

  g_return_val_if_fail (s != NULL, FALSE);

  g_return_val_if_fail (gst_structure_has_name (s, QUICLIB_CONNECTION_STATE),
      FALSE);

  gst_structure_set (s,
      QUICLIB_CONTEXT_MODE, quiclib_mode_get_type (), mode,
      NULL);

  gst_structure_set (s,
      QUICLIB_CONNECTION_STATE, gst_quiclib_transport_state_get_type (), state,
      NULL);

  gst_structure_set (s,
      QUICLIB_CONNECTION_LOCAL, G_TYPE_SOCKET_ADDRESS, local,
      NULL);

  gst_structure_set (s,
      QUICLIB_CONNECTION_PEER, G_TYPE_SOCKET_ADDRESS, peer,
      NULL);

  return TRUE;
}

gboolean
gst_query_parse_quiclib_conn_state (GstQuery *query, GstQUICMode *mode,
    GstQuicLibTransportState *state, GSocketAddress **local,
    GSocketAddress **peer)
{
  const GstStructure *s;
  const GValue *sa_box;

  s = gst_query_get_structure (query);

  g_return_val_if_fail (s, FALSE);

  if (mode != NULL) {
    g_return_val_if_fail (
        gst_structure_get_enum (s,
            QUICLIB_CONTEXT_MODE, quiclib_mode_get_type (), (gint *) mode),
        FALSE);
  }

  if (state != NULL) {
    g_return_val_if_fail (
        gst_structure_get_enum (s, QUICLIB_CONNECTION_STATE,
            gst_quiclib_transport_state_get_type (), (gint *) state), FALSE);
  }

  if (local != NULL) {
    sa_box = gst_structure_get_value (s, QUICLIB_CONNECTION_LOCAL);
    if (sa_box) {
      *local = G_SOCKET_ADDRESS (g_value_get_object (sa_box));
    }
  }

  if (peer != NULL) {
    sa_box = gst_structure_get_value (s, QUICLIB_CONNECTION_PEER);
    if (sa_box) {
      *peer = G_SOCKET_ADDRESS (g_value_get_object (sa_box));
    }
  }

  return TRUE;
}

GstQuery *
gst_query_new_quiclib_stream (GstQuicLibStreamType type)
{
  GstQuery *query;
  GstStructure *s;

  s = gst_structure_new (QUICLIB_STREAM_OPEN,
      QUICLIB_STREAM_TYPE, quiclib_stream_type_get_type (), type,
      NULL);

  query = gst_query_new_custom (GST_QUERY_CUSTOM, s);

  return query;
}

gboolean
gst_query_fill_new_quiclib_stream (GstQuery *query, guint64 stream_id,
    GstQuicLibStreamState state)
{
  GstStructure *s;

  g_return_val_if_fail (query, FALSE);

  s = gst_query_writable_structure (query);

  g_return_val_if_fail (s != NULL, FALSE);

  g_return_val_if_fail (gst_structure_has_name (s, QUICLIB_STREAM_OPEN),
      FALSE);

  gst_structure_set (s,
      QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id,
      NULL);

  gst_structure_set (s,
      QUICLIB_STREAM_STATE, quiclib_stream_status_get_type (), state,
      NULL);

  return TRUE;
}

gboolean
gst_query_parse_new_quiclib_stream (GstQuery *query, guint64 *stream_id,
    GstQuicLibStreamState *state)
{
  const GstStructure *s;

  s = gst_query_get_structure (query);

  g_return_val_if_fail (s, FALSE);
  g_return_val_if_fail (gst_structure_has_name (s, QUICLIB_STREAM_OPEN),
      FALSE);

  g_return_val_if_fail (
      gst_structure_get_uint64 (s, QUICLIB_STREAMID_KEY, stream_id), FALSE);

  g_return_val_if_fail (gst_structure_get_enum (s, QUICLIB_STREAM_STATE,
      quiclib_stream_status_get_type (), (gint *) state), FALSE);

  return TRUE;
}

GstQuery *
gst_query_quiclib_stream_state (guint64 stream_id)
{
  GstQuery *query;
  GstStructure *s;

  s = gst_structure_new (QUICLIB_STREAM_STATE,
      QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id,
      NULL);

  query = gst_query_new_custom (GST_QUERY_CUSTOM, s);

  return query;
}

gboolean
gst_query_fill_quiclib_stream_state (GstQuery *query,
    GstQuicLibStreamState state)
{
  GstStructure *s;

  g_return_val_if_fail (query, FALSE);

  s = gst_query_writable_structure (query);

  g_return_val_if_fail (s != NULL, FALSE);

  g_return_val_if_fail (gst_structure_has_name (s, QUICLIB_STREAM_STATE),
      FALSE);

  gst_structure_set (s,
      QUICLIB_STREAM_STATE, quiclib_stream_status_get_type (), state,
      NULL);

  return TRUE;
}

gboolean
gst_query_parse_quiclib_stream_state (GstQuery *query,
    GstQuicLibStreamState *state)
{
  const GstStructure *s;

  s = gst_query_get_structure (query);

  g_return_val_if_fail (s, FALSE);

  g_return_val_if_fail (gst_structure_get_enum (s, QUICLIB_STREAM_STATE,
      quiclib_stream_status_get_type (), (gint *) state), FALSE);

  return TRUE;
}

gboolean
gst_quiclib_stream_state_is_okay (GstQuicLibStreamState state)
{
  return state < QUIC_STREAM_ERROR_MAX_STREAMS;
}

GstQuery *
gst_query_cancel_quiclib_stream (guint64 stream_id, guint64 reason)
{
  GstQuery *query;
  GstStructure *s;

  s = gst_structure_new (QUICLIB_STREAM_CLOSE,
      QUICLIB_STREAMID_KEY, G_TYPE_UINT64, stream_id,
      QUICLIB_CANCEL_REASON, G_TYPE_UINT64, reason,
      NULL);

  query = gst_query_new_custom (GST_QUERY_CUSTOM, s);

  return query;
}

gboolean
gst_query_parse_cancelled_stream (GstQuery *query, guint64 *stream_id,
    guint64 *reason)
{
  const GstStructure *s;

  s = gst_query_get_structure (query);

  g_return_val_if_fail (s, FALSE);

  g_return_val_if_fail (
      gst_structure_get_uint64 (s, QUICLIB_STREAMID_KEY, stream_id), FALSE);

  g_return_val_if_fail (
      gst_structure_get_uint64 (s, QUICLIB_CANCEL_REASON, reason), FALSE);

  return TRUE;
}

GType
quiclib_mode_get_type (void)
{
  static GType type = 0;
  static const GEnumValue quiclib_mode_types[] = {
      {QUICLIB_MODE_CLIENT, "QUIC Client", "client"},
      {QUICLIB_MODE_SERVER, "QUIC Server", "server"},
      {0, NULL, NULL}
  };

  if (g_once_init_enter (&type)) {
    GType _type = g_enum_register_static ("GstQUICMode", quiclib_mode_types);
    g_once_init_leave (&type, _type);
  }

  return type;
}

GType
quiclib_stream_type_get_type (void)
{
  static GType type = 0;
  static const GEnumValue quiclib_stream_types[] = {
      {QUIC_STREAM_BIDI, "Bidirectional stream", "bidi"},
      {QUIC_STREAM_UNI, "Unidirectional stream", "uni"},
      {0, NULL, NULL}
  };

  if (g_once_init_enter (&type)) {
    GType _type = g_enum_register_static ("GstQuicLibStreamType",
        quiclib_stream_types);
    g_once_init_leave (&type, _type);
  }

  return type;
}

GType
quiclib_stream_status_get_type (void)
{
  static GType type = 0;
  static const GEnumValue quiclib_stream_states[] = {
      {QUIC_STREAM_OPEN, "Stream open", "open"},
      {QUIC_STREAM_DATA_BLOCKED, "Stream data blocked", "data-blocked"},
      {QUIC_STREAM_OPEN_DATA_BLOCKED,
          "Stream open, data blocked by flow control", "open-data-blocked"},
      {QUIC_STREAM_CONNECTION_BLOCKED,
          "Connection blocked by flow control", "conn-blocked"},
      {QUIC_STREAM_OPEN_CONNECTION_BLOCKED,
          "Stream open, connection blocked by flow control",
          "open-conn-blocked"},
      {QUIC_STREAM_OPEN_CONNECTION_AND_DATA_BLOCKED,
          "Stream open, connection and data blocked by flow control",
          "open-conn-data-blocked"},
      {QUIC_STREAM_CLOSED_SENDING,
          "Closed in the sending direction", "closed-sending"},
      {QUIC_STREAM_OPEN_CLOSED_SENDING,
          "Stream open, closed in the sending direction",
          "open-closed-sending"},
      {QUIC_STREAM_CLOSED_READING,
          "Closed in the reading direction", "closed-reading"},
      {QUIC_STREAM_OPEN_CLOSED_READING,
          "Stream open, closed in the reading direction",
          "open-closed-reading"},
      {QUIC_STREAM_CLOSED_BOTH, "Stream closed in both directions", "closed"},
      {QUIC_STREAM_ERROR_MAX_STREAMS,
          "Max streams limit reached", "max-streams"},
      {QUIC_STREAM_ERROR_CONNECTION,
          "Miscellaneous connection error", "conn-error"},
      {QUIC_STREAM_ERROR_CONNECTION_IN_INITIAL,
          "Connection in initial state", "conn-in-initial"},
      {QUIC_STREAM_ERROR_CONNECTION_CLOSED, "Connection closed",
          "conn-closed"},
      {0, NULL, NULL}
  };

  if (g_once_init_enter (&type)) {
    GType _type = g_enum_register_static ("GstQuicLibStreamState", quiclib_stream_states);
    g_once_init_leave (&type, _type);
  }

  return type;
}

static void
gst_quiclib_common_transport_user_init (gpointer g_iface, gpointer iface_data)
{
  GstQuicLibTransportUserInterface *iface =
      (GstQuicLibTransportUserInterface *) g_iface;

  iface->test_alpn = NULL;
  iface->new_connection = quiclib_common_transport_new_connection;
  iface->handshake_complete = quiclib_common_transport_handshake_complete;
  iface->stream_opened = quiclib_common_transport_stream_opened;
  iface->stream_closed = quiclib_common_transport_stream_closed;
  iface->stream_data = quiclib_common_transport_stream_data;
  iface->stream_ackd = quiclib_common_transport_stream_ackd;
  iface->datagram_ackd = quiclib_common_transport_datagram_ackd;
  iface->connection_error = quiclib_common_transport_connection_error;
  iface->connection_closed = quiclib_common_transport_connection_closed;
}

static void
gst_quiclib_common_user_class_init (GstQuicLibCommonUserInterface *iface)
{

}

GType
gst_quiclib_common_user_get_type (void)
{
  static GType type = 0;

  if (g_once_init_enter (&type)) {
    GType _type;
    static const GTypeInfo info = {
        sizeof (GstQuicLibCommonUserInterface),
        NULL,
        NULL,
        (GClassInitFunc) gst_quiclib_common_user_class_init,
        NULL,
        NULL,
        0,
        0,
        NULL
    };
    _type = g_type_register_static (G_TYPE_INTERFACE, "GstQuicLibCommonUser",
        &info, 0);
    g_type_interface_add_prerequisite (_type, G_TYPE_OBJECT);

    g_once_init_leave (&type, _type);
  }
  return type;
}
