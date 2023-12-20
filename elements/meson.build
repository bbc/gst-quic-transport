plugin_c_args = ['-DHAVE_CONFIG_H']

cdata = configuration_data()
cdata.set_quoted('PACKAGE_VERSION', gst_version)
cdata.set_quoted('PACKAGE', 'gst-quic-transport')
cdata.set_quoted('GST_LICENSE', 'LGPL')
cdata.set_quoted('GST_API_VERSION', api_version)
cdata.set_quoted('GST_PACKAGE_NAME', 'QUIC Transport Plug-ins for GStreamer')
cdata.set_quoted('GST_PACKAGE_ORIGIN', 'https://github.com/bbc/gst-quic-transport')
configure_file(output : 'config.h', configuration : cdata)

quicstreamextras_sources = [
  'gstquicstreamextras.c'
  ]
  
gstquicstreamextras = library('gstquicstreamextras',
  quicstreamextras_sources,
  c_args : plugin_c_args,
  dependencies : [gst_dep, quiclib_dep],
  install : true,
  install_dir : plugins_install_dir,
)

quicstreamextras_dep = declare_dependency(link_with: gstquicstreamextras)

quicsrc_sources = [
  'gstquicsrc.c'
  ]

gstquicsrc = library('gstquicsrc',
  quicsrc_sources,
  c_args : plugin_c_args,
  dependencies : [gst_dep, gstbase_dep, quiclib_dep, quicstream_dep,
    quicdatagram_dep, gio_dep],
  install : true,
  install_dir : plugins_install_dir,
)

quicdemux_sources = [
  'gstquicdemux.c'
  ]

gstquicdemux = library('gstquicdemux',
  quicdemux_sources,
  c_args : plugin_c_args,
  dependencies : [gst_dep, quicutils_dep, quiclib_dep, quicstream_dep,
    quicdatagram_dep, quicstreamextras_dep],
  install : true,
  install_dir : plugins_install_dir,
)

quicmux_sources = [
  'gstquicmux.c'
  ]

gstquicmux = library('gstquicmux',
  quicmux_sources,
  c_args : plugin_c_args,
  dependencies : [gst_dep, quiclib_dep, quicstream_dep, quicdatagram_dep,
    quicstreamextras_dep],
  install : true,
  install_dir : plugins_install_dir,
)

quicsink_sources = [
  'gstquicsink.c'
  ]

gstquicsink = library('gstquicsink',
  quicsink_sources,
  c_args : plugin_c_args,
  dependencies : [gst_dep, gstbase_dep, quiclib_dep, gio_dep],
  install : true,
  install_dir : plugins_install_dir,
)

