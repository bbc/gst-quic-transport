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

#ifndef GST_PLUGIN_SRC_QUICLIB_GSTQUICCOMMON_H_
#define GST_PLUGIN_SRC_QUICLIB_GSTQUICCOMMON_H_

#include <gst/gst.h>
#include <gio/gio.h>
#include "gstquicutil.h"

G_BEGIN_DECLS

#define GST_TYPE_QUICLIB_COMMON ( \
    gst_quiclib_common_get_type())
G_DECLARE_FINAL_TYPE (GstQuicLibCommon,
    gst_quiclib_common, GST, QUICLIB_COMMON, GstObject);

typedef struct _GstQuicLibTransportContext GstQuicLibTransportContext;
typedef struct _GstQuicLibServerContext GstQuicLibServerContext;
typedef struct _GstQuicLibTransportConnection GstQuicLibTransportConnection;

#define QUICLIB_TYPE_MODE quiclib_mode_get_type()
#define QUICLIB_MODE (quiclib_mode_get_type ())

GType quiclib_mode_get_type (void);
typedef enum _GstQUICMode {
	QUICLIB_MODE_CLIENT,
	QUICLIB_MODE_SERVER
} GstQUICMode;

#define QUICLIB_RAW "application/quic"
#define QUICLIB_BIDI_STREAM_CAP "application/quic+stream+bidi"
#define QUICLIB_UNI_STREAM_CAP "application/quic+stream+uni"
#define QUICLIB_DATAGRAM_CAP "application/quic+datagram"

#define QUICLIB_LOCATION_DEFAULT "0.0.0.0:443"
#define QUICLIB_MODE_DEFAULT QUICLIB_MODE_SERVER
#define QUICLIB_ALPN_DEFAULT ""
#define QUICLIB_PRIVKEY_LOCATION_DEFAULT "priv.pem"
#define QUICLIB_CERT_LOCATION_DEFAULT "cert.pem"
#define QUICLIB_MAX_STREAMS_BIDI_DEFAULT 100
#define QUICLIB_MAX_STREAMS_UNI_DEFAULT 100
#define QUICLIB_MAX_STREAM_DATA_DEFAULT 131072
#define QUICLIB_MAX_DATA_DEFAULT GST_QUICLIB_VARINT_MAX

#define QUICLIB_CONTEXT_MODE "quic-ctx-mode"
#define QUICLIB_CLIENT_CONNECT "quic-conn-connect"
#define QUICLIB_HANDSHAKE_COMPLETE "quic-handshake-complete"
#define QUICLIB_CONNECTION_STATE "quic-conn-state"
#define QUICLIB_CONNECTION_LOCAL "quic-conn-local"
#define QUICLIB_CONNECTION_PEER "quic-conn-peer"
#define QUICLIB_CONNECTION_PROTO "quic-conn-proto"
#define QUICLIB_CONNECTION_CLOSE "quic-conn-close"
#define QUICLIB_STREAM_OPEN "quic-stream-open"
#define QUICLIB_STREAM_CLOSE "quic-stream-close"
#define QUICLIB_STREAMID_KEY "quic-stream-id"
#define QUICLIB_CANCEL_REASON "quic-cancel-reason"
#define QUICLIB_STREAM_TYPE "quic-stream-type"
#define QUICLIB_STREAM_STATE "quic-stream-state"
#define QUICLIB_DATAGRAM "quic-datagram"


#define GST_QUICLIB_COMMON_USER_TYPE gst_quiclib_common_user_get_type ()
G_DECLARE_INTERFACE (GstQuicLibCommonUser, gst_quiclib_common_user, \
    GST_QUICLIB, COMMON_USER, GstObject);

struct _GstQuicLibCommonUserInterface {
  GTypeInterface parent;

  gboolean (*new_connection) (GstQuicLibCommonUser *self,
      GstQuicLibTransportContext *ctx, GInetSocketAddress *remote,
      const gchar *alpn);

  gboolean (*handshake_complete) (GstQuicLibCommonUser *self,
      GstQuicLibTransportContext *ctx, GInetSocketAddress *remote,
      const gchar *alpn, GstQuicLibTransportConnection *conn);

  gboolean (*stream_opened) (GstQuicLibCommonUser *self,
      GstQuicLibTransportContext *ctx, guint64 stream_id);

  void (*stream_closed) (GstQuicLibCommonUser *self,
      GstQuicLibTransportContext *ctx, guint64 stream_id);

  void (*stream_data) (GstQuicLibCommonUser *self,
      GstQuicLibTransportContext *ctx, GstBuffer *buf);

  void (*stream_ackd) (GstQuicLibCommonUser *self,
      GstQuicLibTransportContext *ctx, guint64 stream_id, gsize ackd_offset);

  void (*datagram_data) (GstQuicLibCommonUser *self,
      GstQuicLibTransportContext *ctx, GstBuffer *buf);

  void (*datagram_ackd) (GstQuicLibCommonUser *self,
      GstQuicLibTransportContext *ctx, guint64 datagram_ticket);

  gboolean (*connection_error) (GstQuicLibCommonUser *self,
      GstQuicLibTransportContext *ctx, guint64 error);

  void (*connection_closed) (GstQuicLibCommonUser *self,
      GstQuicLibTransportContext *ctx, GInetSocketAddress *remote);
};

GstQuicLibServerContext *
gst_quiclib_listen (GstQuicLibCommonUser *user, const gchar *location,
    const gchar *alpns, const gchar *privkey_location,
    const gchar *cert_location, const gchar *sni);

GstQuicLibTransportConnection *
gst_quiclib_connect (GstQuicLibCommonUser *user, const gchar *location,
    const gchar *alpn);

GInetSocketAddress *
gst_quiclib_get_connection_peer (GstQuicLibTransportContext *conn);

void
gst_quiclib_unref (GstQuicLibTransportContext *ctx,
    GstQuicLibCommonUser *user);

gboolean
gst_quiclib_new_handshake_complete_event (GstPad *pad, GSocketAddress *peer,
    const gchar *alpn);

/*
 * *alpn -> transfer FULL (caller needs to free)
 */
gboolean
gst_quiclib_parse_handshake_complete_event (GstEvent *event,
    GSocketAddress **peer, gchar **alpn);

/*
 * TODO: Make new GstEvent types for all these events for easier switch/casing?
 */
gboolean
gst_quiclib_new_stream_opened_event (GstPad *pad, guint64 stream_id);

gboolean
gst_quiclib_parse_stream_opened_event (GstEvent *event, guint64 *stream_id);

gboolean
gst_quiclib_new_stream_closed_event (GstPad *pad, guint64 stream_id);

gboolean
gst_quiclib_parse_stream_closed_event (GstEvent *event, guint64 *stream_id);

gboolean
gst_quiclib_new_connection_error_pad_event (GstPad *pad, guint64 error);

gboolean
gst_quiclib_new_connection_error_element_event (GstElement *element,
    guint64 error);

gboolean
gst_quiclib_parse_connection_error_event (GstEvent *event, guint64 *error);

/*gboolean
gst_quiclib_new_stream_error_pad_event (GstPad *pad, guint64 stream_id,
    guint64 error);

gboolean
gst_quiclib_new_stream_error_element_event (GstElement *element,
    guint64 stream_id, guint64 error);

gboolean
gst_quiclib_parse_stream_error_event (GstEvent *event, guint64 *stream_id,
    guint64 *error);*/

GType quiclib_stream_type_get_type (void);
typedef enum _GstQuicLibStreamType {
  QUIC_STREAM_BIDI,
  QUIC_STREAM_UNI
} GstQuicLibStreamType;

GstQuicLibStreamType
gst_quiclib_get_stream_type_from_id (guint64 stream_id);

GType quiclib_stream_status_get_type (void);
typedef enum _GstQuicLibStreamState {
  QUIC_STREAM_OPEN = 0x1,
  QUIC_STREAM_DATA_BLOCKED = 0x2,
  QUIC_STREAM_OPEN_DATA_BLOCKED = 0x3,
  QUIC_STREAM_CONNECTION_BLOCKED = 0x4,
  QUIC_STREAM_OPEN_CONNECTION_BLOCKED = 0x5,
  QUIC_STREAM_OPEN_CONNECTION_AND_DATA_BLOCKED = 0x7,
  QUIC_STREAM_CLOSED_SENDING = 0x10,
  QUIC_STREAM_OPEN_CLOSED_SENDING = 0x11,
  QUIC_STREAM_CLOSED_READING = 0x20,
  QUIC_STREAM_OPEN_CLOSED_READING = 0x21,
  QUIC_STREAM_CLOSED_BOTH = 0x30,
  QUIC_STREAM_ERROR_MAX_STREAMS = 0x100,
  QUIC_STREAM_ERROR_CONNECTION = 0x1000,
  QUIC_STREAM_ERROR_CONNECTION_IN_INITIAL = 0x3000,
  QUIC_STREAM_ERROR_CONNECTION_CLOSED = 0x5000,
} GstQuicLibStreamState;

typedef enum _GstQuicLibTransportState GstQuicLibTransportState;
typedef enum _GstQuicLibTransportContextMode GstQuicLibTransportContextMode;

GstQuery *
gst_query_new_quiclib_client_connect (GSocketAddress *peer, const gchar *alpn);

GstQuery *
gst_query_new_quiclib_conn_state ();

gboolean
gst_query_fill_quiclib_conn_state (GstQuery *query, GstQUICMode mode,
    GstQuicLibTransportState state, GSocketAddress *local,
    GSocketAddress *peer);

gboolean
gst_query_parse_quiclib_conn_state (GstQuery *query, GstQUICMode *mode,
    GstQuicLibTransportState *state, GSocketAddress **local,
    GSocketAddress **peer);

GstQuery *
gst_query_new_quiclib_stream (GstQuicLibStreamType type);

gboolean
gst_query_fill_new_quiclib_stream (GstQuery *query, guint64 stream_id,
    GstQuicLibStreamState state);

gboolean
gst_query_parse_new_quiclib_stream (GstQuery *query, guint64 *stream_id,
    GstQuicLibStreamState *state);

GstQuery *
gst_query_quiclib_stream_state (guint64 stream_id);

gboolean
gst_query_fill_quiclib_stream_state (GstQuery *query,
    GstQuicLibStreamState state);

gboolean
gst_query_parse_quiclib_stream_state (GstQuery *query,
    GstQuicLibStreamState *state);

gboolean
gst_quiclib_stream_state_is_okay (GstQuicLibStreamState state);

gboolean
gst_quiclib_stream_can_send (GstQuicLibStreamState state);

GstQuery *
gst_query_cancel_quiclib_stream (guint64 stream_id, guint64 reason);

gboolean
gst_query_parse_cancelled_stream (GstQuery *query, guint64 *stream_id,
    guint64 *reason);

#define GST_QUICLIB_ADDRESS_LIST (gst_quiclib_address_list_get_type ())

typedef GList GstQuicLibAddressList;

GType gst_quiclib_address_list_get_type (void);
GstQuicLibAddressList * gst_quiclib_address_list_copy (GstQuicLibAddressList *l);
void gst_quiclib_address_list_free (GstQuicLibAddressList *l);

#define PROP_QUIC_ENDPOINT_COMMON_ENUMS \
  PROP_LOCATION, \
  PROP_MODE, \
  PROP_PEER_ADDRESSES, \
  PROP_LOCAL_ADDRESSES, \
  PROP_MAX_STREAMS_BIDI_LOCAL, \
  PROP_MAX_STREAMS_BIDI_REMOTE, \
  PROP_MAX_STREAMS_UNI_LOCAL, \
  PROP_MAX_STREAMS_UNI_REMOTE, \
  PROP_MAX_STREAM_DATA_BIDI_LOCAL, \
  PROP_MAX_STREAM_DATA_BIDI_REMOTE, \
  PROP_MAX_STREAM_DATA_UNI_LOCAL, \
  PROP_MAX_STREAM_DATA_UNI_REMOTE, \
  PROP_MAX_DATA_LOCAL, \
  PROP_MAX_DATA_REMOTE

#define PROP_QUIC_ENDPOINT_SERVER_ENUMS \
  PROP_ALPN, \
  PROP_PRIVKEY_LOCATION, \
  PROP_CERT_LOCATION, \
  PROP_SNI

#define PROP_QUIC_ENDPOINT_CLIENT_ENUMS \
  PROP_BIDI_STREAMS_REMAINING_LOCAL, \
  PROP_BIDI_STREAMS_REMAINING_REMOTE, \
  PROP_UNI_STREAMS_REMAINING_LOCAL, \
  PROP_UNI_STREAMS_REMAINING_REMOTE

#define PROP_QUIC_ENDPOINT_ENUMS \
  PROP_QUIC_ENDPOINT_COMMON_ENUMS, \
  PROP_QUIC_ENDPOINT_SERVER_ENUMS, \
  PROP_QUIC_ENDPOINT_CLIENT_ENUMS

/**
 * Purposefully misses the first case and the final colon so when used inline
 * it doesn't break syntax:
 *
 * switch (foo) {
 *   case PROP_QUIC_ENDPOINT_COMMON_ENUM_CASES:
 *     gst_quiclib_common_(get|set)_endpoint_property_checked (...);
 *     break;
 *   case PROP_OTHER:
 *     (...)
 *     break;
 *   default:
 *     (...)
 * }
 */
#define PROP_QUIC_ENDPOINT_COMMON_ENUM_CASES PROP_LOCATION: \
  case PROP_MODE: \
  case PROP_ALPN: \
  case PROP_PEER_ADDRESSES: \
  case PROP_LOCAL_ADDRESSES: \
  case PROP_MAX_STREAMS_BIDI_LOCAL: \
  case PROP_MAX_STREAMS_BIDI_REMOTE: \
  case PROP_MAX_STREAMS_UNI_LOCAL: \
  case PROP_MAX_STREAMS_UNI_REMOTE: \
  case PROP_MAX_STREAM_DATA_BIDI_LOCAL: \
  case PROP_MAX_STREAM_DATA_BIDI_REMOTE: \
  case PROP_MAX_STREAM_DATA_UNI_LOCAL: \
  case PROP_MAX_STREAM_DATA_UNI_REMOTE: \
  case PROP_MAX_DATA_LOCAL: \
  case PROP_MAX_DATA_REMOTE

#define PROP_QUIC_ENDPOINT_SERVER_ENUM_CASES PROP_PRIVKEY_LOCATION: \
  case PROP_CERT_LOCATION: \
  case PROP_SNI \

#define PROP_QUIC_ENDPOINT_CLIENT_ENUM_CASES PROP_BIDI_STREAMS_REMAINING_LOCAL:\
  case PROP_BIDI_STREAMS_REMAINING_REMOTE: \
  case PROP_UNI_STREAMS_REMAINING_LOCAL: \
  case PROP_UNI_STREAMS_REMAINING_REMOTE

#define PROP_QUIC_ENDPOINT_ENUM_CASES PROP_QUIC_ENDPOINT_COMMON_ENUM_CASES: \
  case PROP_QUIC_ENDPOINT_SERVER_ENUM_CASES: \
  case PROP_QUIC_ENDPOINT_CLIENT_ENUM_CASES

#define QUIC_ENDPOINT_PROPERTIES \
  gchar *location; \
  GstQUICMode mode; \
  gchar *alpn; \
  gchar *privkey_location; \
  gchar *cert_location; \
  gchar *sni; \
  guint64 max_streams_bidi_remote_init; \
  guint64 max_streams_uni_remote_init; \
  guint64 max_stream_data_bidi_remote_init; \
  guint64 max_stream_data_uni_remote_init; \
  guint64 max_data_remote_init;

#define gst_quiclib_common_init_endpoint_properties(inst) \
  do { \
    inst->location = g_strdup (QUICLIB_LOCATION_DEFAULT); \
    inst->mode = QUICLIB_MODE_SERVER; \
    inst->alpn = g_strdup (QUICLIB_ALPN_DEFAULT); \
    inst->privkey_location = g_strdup (QUICLIB_PRIVKEY_LOCATION_DEFAULT); \
    inst->cert_location = g_strdup (QUICLIB_CERT_LOCATION_DEFAULT); \
    inst->sni = g_strdup (g_get_host_name ()); \
    inst->max_streams_bidi_remote_init = QUICLIB_MAX_STREAMS_BIDI_DEFAULT; \
    inst->max_streams_uni_remote_init = QUICLIB_MAX_STREAMS_UNI_DEFAULT; \
    inst->max_stream_data_bidi_remote_init = QUICLIB_MAX_STREAM_DATA_DEFAULT; \
    inst->max_stream_data_uni_remote_init = QUICLIB_MAX_STREAM_DATA_DEFAULT; \
    inst->max_data_remote_init = QUICLIB_MAX_DATA_DEFAULT; \
  } while (0);

#define gst_quiclib_common_install_endpoint_properties(klass) \
  do { \
    gst_quiclib_common_install_location_property (klass); \
    gst_quiclib_common_install_mode_property (klass); \
    gst_quiclib_common_install_alpn_property (klass); \
    gst_quiclib_common_install_peer_addresses_property (klass); \
    gst_quiclib_common_install_local_addresses_property (klass); \
    gst_quiclib_common_install_privkey_location_property (klass); \
    gst_quiclib_common_install_cert_location_property (klass); \
    gst_quiclib_common_install_sni_property (klass); \
    gst_quiclib_common_install_max_streams_bidi_local_property (klass); \
    gst_quiclib_common_install_max_streams_bidi_remote_property (klass); \
    gst_quiclib_common_install_bidi_streams_remaining_local_property (klass); \
    gst_quiclib_common_install_bidi_streams_remaining_remote_property (klass); \
    gst_quiclib_common_install_max_streams_uni_local_property (klass); \
    gst_quiclib_common_install_max_streams_uni_remote_property (klass); \
    gst_quiclib_common_install_uni_streams_remaining_local_property (klass); \
    gst_quiclib_common_install_uni_streams_remaining_remote_property (klass); \
    gst_quiclib_common_install_max_stream_data_bidi_local_property (klass); \
    gst_quiclib_common_install_max_stream_data_bidi_remote_property (klass); \
    gst_quiclib_common_install_max_stream_data_uni_local_property (klass); \
    gst_quiclib_common_install_max_stream_data_uni_remote_property (klass); \
    gst_quiclib_common_install_max_data_local_property (klass); \
    gst_quiclib_common_install_max_data_remote_property (klass); \
  } while (0); \

#define PROP_LOCATION_SHORT "location"
#define gst_quiclib_common_install_location_property(klass) \
  g_object_class_install_property (klass, PROP_LOCATION, \
      g_param_spec_string (PROP_LOCATION_SHORT, "Location", \
          "Location to connect to in client mode, or listening address in " \
          "server mode", \
          QUICLIB_LOCATION_DEFAULT, \
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

/*
 * TODO: Is this redundant? Remove?
 */
#define PROP_MODE_SHORTNAME "mode"
#define gst_quiclib_common_install_mode_property(klass) \
  g_object_class_install_property (klass, PROP_MODE, \
      g_param_spec_enum (PROP_MODE_SHORTNAME, "Mode", "Client or server mode", \
          QUICLIB_TYPE_MODE, QUICLIB_MODE_DEFAULT, \
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

#define PROP_ALPN_SHORTNAME "alpn"
#define gst_quiclib_common_install_alpn_property(klass) \
  g_object_class_install_property (klass, PROP_ALPN, \
      g_param_spec_string (PROP_ALPN_SHORTNAME, "Acceptable ALPNs", \
          "The ALPN to negotiate in client mode, or a comma-separated list of" \
          " ALPNs to accept in server mode", QUICLIB_ALPN_DEFAULT, \
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

#define PROP_PEER_ADDRESSES_SHORTNAME "peer-addr"
#define gst_quiclib_common_install_peer_addresses_property(klass) \
  g_object_class_install_property (klass, PROP_PEER_ADDRESSES, \
      g_param_spec_boxed (PROP_PEER_ADDRESSES_SHORTNAME, "Peer addresses", \
          "A GList of GSocketAddress objects relating to addresses of the " \
          "peer in a QUIC connection. An empty list implies there is no " \
          "active connection.", GST_QUICLIB_ADDRESS_LIST, G_PARAM_READABLE));

#define PROP_LOCAL_ADDRESSES_SHORTNAME "local-addr"
#define gst_quiclib_common_install_local_addresses_property(klass) \
  g_object_class_install_property (klass, PROP_LOCAL_ADDRESSES, \
      g_param_spec_boxed (PROP_LOCAL_ADDRESSES_SHORTNAME, "Local addresses", \
          "A GList of GSocketAddress objects relating to local addresses of " \
          "the QUIC connection. An empty list implies there is no active " \
          "client connection, or there is no server listening address.", \
		  GST_QUICLIB_ADDRESS_LIST, G_PARAM_READABLE));

#define PROP_PRIVKEY_LOCATION_SHORTNAME "privkey"
#define gst_quiclib_common_install_privkey_location_property(klass) \
  g_object_class_install_property (klass, PROP_PRIVKEY_LOCATION, \
      g_param_spec_string (PROP_PRIVKEY_LOCATION_SHORTNAME, \
          "Private Key Location", \
          "The location of the private key for use in server mode", \
          QUICLIB_PRIVKEY_LOCATION_DEFAULT, \
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

#define PROP_CERT_LOCATION_SHORTNAME "cert"
#define gst_quiclib_common_install_cert_location_property(klass) \
  g_object_class_install_property (klass, PROP_CERT_LOCATION, \
      g_param_spec_string (PROP_CERT_LOCATION_SHORTNAME, \
          "Certificate Location", \
          "The location of the certificate to present in server mode", \
          QUICLIB_CERT_LOCATION_DEFAULT, \
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

#define PROP_SNI_SHORTNAME "sni"
#define gst_quiclib_common_install_sni_property(klass) \
  g_object_class_install_property (klass, PROP_SNI, \
      g_param_spec_string (PROP_SNI_SHORTNAME, "Server Name Indication", \
          "The SNI to present in server mode", g_get_host_name (), \
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

#define PROP_MAX_STREAMS_BIDI_LOCAL_SHORTNAME "max-streams-bidi-local"
#define gst_quiclib_common_install_max_streams_bidi_local_property(klass) \
  g_object_class_install_property (klass, PROP_MAX_STREAMS_BIDI_LOCAL, \
      g_param_spec_uint64 (PROP_MAX_STREAMS_BIDI_LOCAL_SHORTNAME, \
          "Max local bidi streams", \
          "The maximum number of bidirectional streams this endpoint is " \
          "permitted to open", 0, QUICLIB_VARINT_MAX / 4, 0, \
		  G_PARAM_READABLE));

#define PROP_MAX_STREAMS_BIDI_REMOTE_SHORTNAME "max-streams-bidi-remote"
#define gst_quiclib_common_install_max_streams_bidi_remote_property(klass) \
  g_object_class_install_property (klass, PROP_MAX_STREAMS_BIDI_REMOTE, \
      g_param_spec_uint64 (PROP_MAX_STREAMS_BIDI_REMOTE_SHORTNAME, \
          "Max remote bidi streams", \
          "The maximum number of bidirectional streams peers are permitted to" \
          " open", 0, QUICLIB_VARINT_MAX / 4, \
          QUICLIB_MAX_STREAMS_BIDI_DEFAULT, G_PARAM_READWRITE));

#define PROP_BIDI_STREAMS_REMAINING_LOCAL_SHORTNAME \
  "bidi-streams-remaining-local"
#define gst_quiclib_common_install_bidi_streams_remaining_local_property( \
    klass) \
  g_object_class_install_property (klass, PROP_BIDI_STREAMS_REMAINING_LOCAL, \
      g_param_spec_uint64 (PROP_BIDI_STREAMS_REMAINING_LOCAL_SHORTNAME, \
          "Local BIDI streams remaining", \
          "The number of bidi streams this endpoint can open at the moment", \
          0, QUICLIB_VARINT_MAX / 4, 0, G_PARAM_READABLE));

#define PROP_BIDI_STREAMS_REMAINING_REMOTE_SHORTNAME \
  "bidi-streams-remaining-remote"
#define gst_quiclib_common_install_bidi_streams_remaining_remote_property( \
    klass) \
  g_object_class_install_property (klass, PROP_BIDI_STREAMS_REMAINING_REMOTE, \
      g_param_spec_uint64 (PROP_BIDI_STREAMS_REMAINING_REMOTE_SHORTNAME, \
          "Remote BIDI streams remaining", \
          "The number of bidi streams the peer can open at the moment. "\
          "Changing this value will cause emission of a MAX_STREAMS frame.", \
          0, QUICLIB_VARINT_MAX / 4, 0, G_PARAM_READWRITE));

#define PROP_MAX_STREAMS_UNI_LOCAL_SHORTNAME "max-streams-uni-local"
#define gst_quiclib_common_install_max_streams_uni_local_property(klass) \
  g_object_class_install_property (klass, PROP_MAX_STREAMS_UNI_LOCAL, \
        g_param_spec_uint64 (PROP_MAX_STREAMS_UNI_LOCAL_SHORTNAME, \
            "Max local uni streams", \
            "The maximum number of unidirectional streams this endpoint is " \
            "permitted to open", \
            0, QUICLIB_VARINT_MAX / 4, 0, G_PARAM_READABLE));

#define PROP_MAX_STREAMS_UNI_REMOTE_SHORTNAME "max-streams-uni-remote"
#define gst_quiclib_common_install_max_streams_uni_remote_property(klass) \
    g_object_class_install_property (klass, PROP_MAX_STREAMS_UNI_REMOTE, \
        g_param_spec_uint64 (PROP_MAX_STREAMS_UNI_REMOTE_SHORTNAME, \
            "Max remote uni streams", \
            "The maximum number of unidirectional streams peers are permitted" \
            " to open", 0, QUICLIB_VARINT_MAX / 4, \
            QUICLIB_MAX_STREAMS_UNI_DEFAULT, G_PARAM_READWRITE));

#define PROP_UNI_STREAMS_REMAINING_LOCAL_SHORTNAME "uni-streams-remaining-local"
#define gst_quiclib_common_install_uni_streams_remaining_local_property(klass) \
  g_object_class_install_property (klass, PROP_UNI_STREAMS_REMAINING_LOCAL, \
      g_param_spec_uint64 (PROP_UNI_STREAMS_REMAINING_LOCAL_SHORTNAME, \
          "Local uni streams remaining", \
          "The number of uni streams this endpoint can open at the moment", \
          0, QUICLIB_VARINT_MAX / 4, 0, G_PARAM_READABLE));

#define PROP_UNI_STREAMS_REMAINING_REMOTE_SHORTNAME \
  "uni-streams-remaining-remote"
#define gst_quiclib_common_install_uni_streams_remaining_remote_property(klass) \
  g_object_class_install_property (klass, PROP_UNI_STREAMS_REMAINING_REMOTE, \
      g_param_spec_uint64 (PROP_UNI_STREAMS_REMAINING_REMOTE_SHORTNAME, \
          "Remote uni streams remaining", \
          "The number of uni streams the peer can open at the moment. "\
          "Changing this value will cause emission of a MAX_STREAMS frame.", \
          0, QUICLIB_VARINT_MAX / 4, 0, G_PARAM_READWRITE));

#define PROP_MAX_STREAM_DATA_BIDI_LOCAL_SHORTNAME "max-stream-data-bidi-local"
#define gst_quiclib_common_install_max_stream_data_bidi_local_property(klass) \
    g_object_class_install_property (klass, PROP_MAX_STREAM_DATA_BIDI_LOCAL, \
        g_param_spec_uint64 (PROP_MAX_STREAM_DATA_BIDI_LOCAL_SHORTNAME, \
            "Max local bidi stream data", \
            "The maximum number of bytes this endpoint can send on any " \
            "bidirectional stream",\
            0, QUICLIB_VARINT_MAX, 0, G_PARAM_READABLE));

#define PROP_MAX_STREAM_DATA_BIDI_REMOTE_SHORTNAME "max-stream-data-bidi-remote"
#define gst_quiclib_common_install_max_stream_data_bidi_remote_property(klass) \
    g_object_class_install_property (klass, PROP_MAX_STREAM_DATA_BIDI_REMOTE, \
        g_param_spec_uint64 (PROP_MAX_STREAM_DATA_BIDI_REMOTE_SHORTNAME, \
            "Max remote bidi stream data", \
            "The maximum number of bytes peers can send on any bidirectional " \
            "stream", \
            0, QUICLIB_VARINT_MAX, QUICLIB_MAX_STREAM_DATA_DEFAULT, \
            G_PARAM_READWRITE));

#define PROP_MAX_STREAM_DATA_UNI_LOCAL_SHORTNAME "max-stream-data-uni-local"
#define gst_quiclib_common_install_max_stream_data_uni_local_property(klass) \
    g_object_class_install_property (klass, PROP_MAX_STREAM_DATA_UNI_LOCAL, \
        g_param_spec_uint64 (PROP_MAX_STREAM_DATA_UNI_LOCAL_SHORTNAME, \
            "Max local uni stream data", \
            "The maximum number of bytes this endpoint can send on any " \
            "unidirectional stream",\
            0, QUICLIB_VARINT_MAX, 0, G_PARAM_READABLE));

#define PROP_MAX_STREAM_DATA_UNI_REMOTE_SHORTNAME "max-stream-data-uni-remote"
#define gst_quiclib_common_install_max_stream_data_uni_remote_property(klass) \
    g_object_class_install_property (klass, PROP_MAX_STREAM_DATA_UNI_REMOTE, \
        g_param_spec_uint64 (PROP_MAX_STREAM_DATA_UNI_REMOTE_SHORTNAME, \
            "Max remote uni stream data", \
            "The maximum number of bytes peers can send on any " \
            "unidirectional stream", \
            0, QUICLIB_VARINT_MAX, QUICLIB_MAX_STREAM_DATA_DEFAULT, \
            G_PARAM_READWRITE));

#define PROP_MAX_DATA_LOCAL_SHORTNAME "max-data-local"
#define gst_quiclib_common_install_max_data_local_property(klass) \
    g_object_class_install_property (klass, PROP_MAX_DATA_LOCAL, \
        g_param_spec_uint64 (PROP_MAX_DATA_LOCAL_SHORTNAME, \
            "Max local stream data", \
            "The maximum number of bytes this endpoint can send on this "\
            "connection",\
            0, QUICLIB_VARINT_MAX, 0, G_PARAM_READABLE));

#define PROP_MAX_DATA_REMOTE_SHORTNAME "max-data-remote"
#define gst_quiclib_common_install_max_data_remote_property(klass) \
    g_object_class_install_property (klass, PROP_MAX_DATA_REMOTE, \
        g_param_spec_uint64 (PROP_MAX_DATA_REMOTE_SHORTNAME, \
            "Max remote stream data", \
            "The maximum number of bytes peers can send on this connection", \
            0, QUICLIB_VARINT_MAX, QUICLIB_MAX_STREAM_DATA_DEFAULT, \
            G_PARAM_READWRITE));

#define gst_quiclib_common_set_endpoint_property_checked( \
    obj, tctx, pspec, prop_id, value) \
  do { \
    gboolean set = TRUE; \
    switch (prop_id) { \
      case PROP_LOCATION: \
        if (obj->location != NULL) { \
          g_free (obj->location); \
        } \
        obj->location = g_value_dup_string (value); \
        break; \
      case PROP_MODE: \
        if (tctx != NULL) { \
          g_critical ("Cannot set mode while QUIC context is active!"); \
        } else { \
          obj->mode = g_value_get_enum (value); \
        } \
        set = FALSE; \
        break; \
      case PROP_ALPN: \
        if (obj->alpn != NULL) { \
          g_free (obj->alpn); \
        } \
        obj->alpn = g_value_dup_string (value); \
        break; \
      case PROP_PRIVKEY_LOCATION: \
        if (obj->privkey_location) { \
          g_free (obj->privkey_location); \
        } \
        obj->privkey_location = g_value_dup_string (value); \
        break; \
      case PROP_CERT_LOCATION: \
        if (obj->cert_location) { \
          g_free (obj->cert_location); \
        } \
        obj->cert_location = g_value_dup_string (value); \
        break; \
      case PROP_SNI: \
        if (obj->sni) { \
          g_free (obj->sni); \
        } \
        obj->sni = g_value_dup_string (value); \
        break; \
      case PROP_MAX_STREAMS_BIDI_REMOTE: \
        obj->max_streams_bidi_remote_init = g_value_get_uint64 (value); \
        break; \
      case PROP_BIDI_STREAMS_REMAINING_REMOTE: \
        break; \
      case PROP_MAX_STREAMS_UNI_REMOTE: \
        obj->max_streams_uni_remote_init = g_value_get_uint64 (value); \
        break; \
      case PROP_UNI_STREAMS_REMAINING_REMOTE: \
        break; \
      case PROP_MAX_STREAM_DATA_BIDI_REMOTE: \
        obj->max_stream_data_bidi_remote_init = g_value_get_uint64 (value); \
        break; \
      case PROP_MAX_STREAM_DATA_UNI_REMOTE: \
        obj->max_stream_data_uni_remote_init = g_value_get_uint64 (value); \
        break; \
      case PROP_MAX_DATA_REMOTE: \
        obj->max_data_remote_init = g_value_get_uint64 (value); \
        break; \
      /* Read-only properties start */ \
      case PROP_MAX_STREAMS_BIDI_LOCAL: \
      case PROP_BIDI_STREAMS_REMAINING_LOCAL: \
      case PROP_MAX_STREAMS_UNI_LOCAL: \
      case PROP_UNI_STREAMS_REMAINING_LOCAL: \
      case PROP_MAX_STREAM_DATA_BIDI_LOCAL: \
      case PROP_MAX_STREAM_DATA_UNI_LOCAL: \
      case PROP_MAX_DATA_LOCAL: \
        g_critical ("Cannot set local transport parameters, they are read-only!"); \
        set = FALSE; \
        break; \
    } \
    \
    if (set && tctx != NULL) { \
      g_object_set_property (G_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (tctx)),\
                  pspec->name, value); \
    } \
  } while (0);

#define gst_quiclib_common_get_endpoint_property_checked( \
    obj, tctx, pspec, prop_id, value) \
  do { \
    if (prop_id == PROP_MODE) { \
      g_value_set_enum (value, obj->mode); \
    } else if (tctx) { \
      if (GST_IS_QUICLIB_TRANSPORT_CONNECTION (tctx)) { \
        g_object_get_property (G_OBJECT (tctx), pspec->name, value); \
      } else if (GST_IS_QUICLIB_SERVER_CONTEXT (tctx)) { \
        g_object_get_property (G_OBJECT (tctx), pspec->name, value); \
      } else { \
        g_object_get_property ( \
            G_OBJECT (GST_QUICLIB_TRANSPORT_CONTEXT (tctx)), pspec->name, \
            value); \
      } \
    } else { \
      switch (prop_id) { \
        case PROP_LOCATION:\
          g_value_set_string (value, obj->location); \
          break; \
        case PROP_ALPN: \
          g_value_set_string (value, obj->alpn); \
          break; \
        case PROP_PRIVKEY_LOCATION: \
          g_value_set_string (value, obj->privkey_location); \
          break; \
        case PROP_CERT_LOCATION: \
          g_value_set_string (value, obj->cert_location); \
          break; \
        case PROP_SNI: \
          g_value_set_string (value, obj->sni); \
          break; \
        case PROP_MAX_STREAMS_BIDI_REMOTE: \
          g_value_set_uint64 (value, obj->max_streams_bidi_remote_init); \
          break; \
        case PROP_MAX_STREAMS_UNI_REMOTE: \
          g_value_set_uint64 (value, obj->max_streams_uni_remote_init); \
          break; \
        case PROP_MAX_STREAM_DATA_BIDI_REMOTE: \
          g_value_set_uint64 (value, obj->max_stream_data_bidi_remote_init); \
          break; \
        case PROP_MAX_STREAM_DATA_UNI_REMOTE: \
          g_value_set_uint64 (value, obj->max_stream_data_uni_remote_init); \
          break; \
        case PROP_MAX_DATA_REMOTE: \
          g_value_set_uint64 (value, obj->max_data_remote_init); \
          break; \
        default: \
          GST_DEBUG_OBJECT (obj, "Property %s unavailable when there is " \
              "no transport context", pspec->name); \
      } \
    } \
  } while (0);

/*
 * For debugging only - don't leave in released code!
 */
#if 1
#define GST_QUICLIB_PRINT_BUFFER(ctx, buf)
#else
#define GST_QUICLIB_PRINT_BUFFER(ctx, buf) \
  do { \
    gchar dbgbuf[20000]; \
    gsize write_offset = 0; \
    GstMapInfo map; \
    GstQuicLibStreamMeta *stream_meta; \
    GstQuicLibDatagramMeta *datagram_meta; \
    \
    stream_meta = gst_buffer_get_quiclib_stream_meta (buf); \
    datagram_meta = gst_buffer_get_quiclib_datagram_meta (buf); \
    \
    write_offset = g_snprintf (dbgbuf, 10000, \
        "Buffer %p of length %lu contains:\n", buf, gst_buffer_get_size (buf));\
    \
    if (stream_meta) { \
      write_offset += g_snprintf (dbgbuf + write_offset, 10000 - write_offset, \
          "\tGstQuicLibStreamMeta %p:\n\t\tstream_id %ld\n" \
          "\t\tstream_type: %ld\n\t\toffset: %lu\n\t\tlength: %lu\n" \
          "\t\tfinal: %s\n", stream_meta, stream_meta->stream_id, \
          stream_meta->stream_type, stream_meta->offset, stream_meta->length, \
          stream_meta->final?"TRUE":"FALSE"); \
    } \
    if (datagram_meta) { \
      write_offset += g_snprintf (dbgbuf + write_offset, 10000 - write_offset, \
          "\tGstQuicLibDatagramMeta %p:\n\t\tlength: %lu\n", datagram_meta, \
          datagram_meta->length); \
    } \
    if (!gst_buffer_map (buf, &map, GST_MAP_READ)) { \
      GST_ERROR_OBJECT (ctx, "Couldn't open buffer %p for reading", buf); \
    } else { \
      gint line, num_lines; \
      gsize offset = 0, tot_size = gst_buffer_get_size (buf); \
      \
      num_lines = tot_size / 16; \
      if ((tot_size % 16) != 0) num_lines++; \
      if (num_lines > 180) num_lines = 180; \
      \
      for (line = 0; line < num_lines && write_offset < 10000; line++) { \
        gint c; \
        write_offset += g_snprintf (dbgbuf + write_offset, 10000 - write_offset,\
          "\t"); \
        for (c = 0; c < 16 && offset < tot_size && write_offset < 10000; c++) { \
          write_offset += g_snprintf (dbgbuf + write_offset, \
              10000 - write_offset, "%02x ", map.data[offset++]); \
        } \
        write_offset += g_snprintf (dbgbuf + write_offset, 10000 - write_offset,\
            "\n"); \
      } \
      GST_DEBUG_OBJECT (ctx, "%s", dbgbuf); \
      gst_buffer_unmap (buf, &map); \
    } \
  } while (0);
#endif

G_END_DECLS

#endif /* GST_PLUGIN_SRC_QUICLIB_GSTQUICCOMMON_H_ */
