#!/usr/bin/python
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2019 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
import os, sys, shutil, tarfile
from subprocess import call
import re

dir_out      = "./output/"

hdr_files_vsdk    = ['xr_voice_sdk.h', ]
hdr_files_xrsr    = ['../../../xr-speech-router/generic/src/xrsr.h', ]
hdr_files_xrsv    = ['../../../xr-speech-vrex/generic/src/xrsv.h', ]
hdr_files_xraudio = ['../../../xraudio/generic/src/xraudio_hal.h', '../../../xraudio/generic/src/xraudio_kwd.h', '../../../xraudio/generic/src/xraudio_eos.h', '../../../xraudio/generic/src/xraudio_dga.h',]

def docs_gen_all(build_release=False):
   release_version = '1'
   release_name    = 'vsdk_release_' + release_version
   header_files = hdr_files_vsdk + hdr_files_xrsr + hdr_files_xrsv + hdr_files_xraudio
   cmd = ["doxygen", "vsdk_api_all"]
   ret = call(cmd)
   if build_release:
      build_pdf()
      package_release(release_name, header_files)
   else:
      launch_html()

def launch_html():
   dir_html  = os.path.join(dir_out, 'html')
   file_html = os.path.join(dir_html, 'index.html')
   cmd = ["firefox", file_html ]
   ret = call(cmd)

def build_pdf():
   os.chdir("./output/latex")
   cmd = ["pdflatex", "refman.tex" ]
   ret = call(cmd)
   os.chdir("../..")

def package_release(release_name, header_files):
   dir_html      = os.path.join(dir_out, 'html')
   dir_latex     = os.path.join(dir_out, 'latex')
   dir_rel       = os.path.join(dir_out, release_name)
   dir_rel_html  = os.path.join(dir_rel, 'html')
   file_pdf      = os.path.join(dir_latex, 'refman.pdf')
   file_rel_pdf  = os.path.join(dir_rel, 'hal_api.pdf')
   file_rel_html = os.path.join(dir_rel, 'hal_api.html')
   file_rel_tar  = os.path.join(dir_out, release_name + '.tar.gz')

   if os.path.isdir(dir_rel):
      shutil.rmtree(dir_rel)
      
   # Create release directory
   os.mkdir(dir_rel)
   # Copy html files
   shutil.copytree(dir_html, dir_rel_html)
   
   # Create html shortcut
   fh = open(file_rel_html, 'w')
   fh.write('<html><meta http-equiv="refresh" content="0;url=./html/index.html" /></html>')
   fh.close()
   
   # Copy pdf file
   shutil.copy2(file_pdf, file_rel_pdf)
   
   # Copy header files
   for file in header_files:
      shutil.copy2(os.path.join('..', file), dir_rel)
   
   # tar up the release
   tar = tarfile.open(file_rel_tar, "w:gz")
   tar.add(dir_rel, arcname=release_name)
   tar.close()
   
   # Remove the release directory
   shutil.rmtree(dir_rel)


docs_gen_all(False)
