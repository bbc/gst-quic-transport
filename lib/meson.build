#
# Copyright (c) 2023 British Broadcasting Corporation - Research and Development
#
# Author: Sam Hurst <sam.hurst@bbc.co.uk>
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
# Alternatively, the contents of this file may be used under the
# GNU Lesser General Public License Version 2.1 (the "LGPL"), in
# which case the following provisions apply instead of the ones
# mentioned above:
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.
#

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
  'gstquictransport.c',
  'gstquicpriv.c'
  ]

quiclib = library('gstquiclib',
  quiclib_sources,
  #c_args : plugin_c_args,
  dependencies : [gst_dep, gio_dep, ngtcp2_dep, ngtcp2_crypto_dep, openssl_dep,
    crypto_dep, quicstream_dep, quicdatagram_dep, quicutils_dep],
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
  'gstquicutil.h',
  'gstquicsignals.h'
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
