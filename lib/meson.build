quicutils_sources = [
  'gstquicutil.c'
  ]
  
quicutils = library('gstquicutil',
  quicutils_sources,
  #c_args : plugin_c_args,
  dependencies : [gst_dep],
  install : true,
  install_dir : plugins_install_dir,
  )

quicutils_dep = declare_dependency(link_with: quicutils,
  include_directories: include_directories('.'))

quicstream_sources = [
  'gstquicstream.c'
  ]

quicstream = library('gstquicstream',
  quicstream_sources,
  #c_args : plugin_c_args,
  dependencies : [gst_dep],
  install : true,
  install_dir : plugins_install_dir,
  )

quicstream_dep = declare_dependency(link_with: quicstream,
  include_directories: include_directories('.'))

quicdatagram_sources = [
  'gstquicdatagram.c'
  ]

quicdatagram = library('gstquicdatagram',
  quicdatagram_sources,
  #c_args : plugin_c_args,
  dependencies : [gst_dep],
  install : true,
  install_dir : plugins_install_dir,
  )
  
quicdatagram_dep = declare_dependency(link_with: quicdatagram,
  include_directories: include_directories('.'))

quiclib_sources = [
  'gstquiccommon.c',
  'gstquictransport.c'
  ]

quiclib = library('gstquiclib',
  quiclib_sources,
  #c_args : plugin_c_args,
  dependencies : [gst_dep, gio_dep, ngtcp2_dep, ngtcp2_crypto_dep, openssl_dep,
    crypto_dep, quicstream_dep, quicdatagram_dep],
  install : true,
  install_dir : plugins_install_dir,
  )

quiclib_dep = declare_dependency(link_with: quiclib,
  include_directories: include_directories('.'))

quiclib_all_headers = [
  'gstquiccommon.h',
  'gstquicdatagram.h',
  'gstquicstream.h',
  'gstquictransport.h',
  'gstquicutil.h'
  ]

install_headers (quiclib_all_headers, subdir : meson.project_name())

#
# TODO: Separate these out into their own pkg-config files?
#
pkg_mod = import ('pkgconfig')
#pkg_mod.generate(
#  name : meson.project_name(),
#  filebase : meson.project_name(),
#  description: 'QUIC Transport library for GStreamer',
#  subdirs : meson.project_name(),
#  libraries : [quiclib, quicutils, quicstream, quicdatagram]
#)

pkg_mod.generate(
  name : quiclib.name(),
  filebase : quiclib.name(),
  description: 'QUIC Transport library for GStreamer',
  subdirs : quiclib.name(),
  libraries : quiclib
)

pkg_mod.generate(
  name : quicutils.name(),
  filebase : quicutils.name(),
  description : 'QUIC Utility library for GStreamer',
  subdirs : quicutils.name(),
  libraries : quicutils
)

pkg_mod.generate(
  name : quicstream.name(),
  filebase : quicstream.name(),
  description : 'QUIC Stream functions for GStreamer',
  subdirs : quicstream.name(),
  libraries : quicstream
)

pkg_mod.generate(
  name : quicdatagram.name(),
  filebase : quicdatagram.name(),
  description : 'QUIC Datagram functions for GStreamer',
  subdirs : quicdatagram.name(),
  libraries : quicdatagram
)