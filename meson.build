project ('gst-quic-transport', 'c', version : '0.0.1', license : 'LGPL')

plugins_install_dir = join_paths(get_option('libdir'), 'gstreamer-1.0')

cc = meson.get_compiler('c')

gst_version = meson.project_version()

api_version = '1.0'

gst_dep = dependency('gstreamer-1.0',
  version : '>=1.20',
  required : true,
  fallback : ['gstreamer', 'gst_dep'])

gstbase_dep = dependency('gstreamer-base-1.0',
  version : '>=1.20',
  fallback : ['gstreamer', 'gst_base_dep'])
  
gio_dep = dependency('gio-2.0',
  required : true)

ngtcp2_dep = dependency('libngtcp2')

ngtcp2_crypto_dep = dependency('libngtcp2_crypto_quictls')

openssl_dep = dependency('libssl')

crypto_dep = dependency ('libcrypto')

subdir('lib')
subdir('elements')
