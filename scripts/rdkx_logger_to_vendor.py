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
import os,sys,json

if len(sys.argv) != 3:
   raise ValueError('Invalid input quantity {}'.format(len(sys.argv)))

file_hdr_in  = sys.argv[1]
file_hdr_out = sys.argv[2]


replacements = {
   'xlog_modules':   'xlog_vendor_modules',
   'xlog_init':      'xlog_vendor_init',
   'xlog_term':      'xlog_vendor_term',
   'xlog_level':     'xlog_vendor_level',
   'xlog_printf':    'xlog_vendor_printf',
   'xlog_fprintf':   'xlog_vendor_fprintf',
   'xlog_dprintf':   'xlog_vendor_dprintf',
   'xlog_snprintf':  'xlog_vendor_snprintf',
   'xlog_vfprintf':  'xlog_vendor_vfprintf',
   'xlog_vdprintf':  'xlog_vendor_vdprintf',
   'xlog_vsnprintf': 'xlog_vendor_vsnprintf',
}

# Read input file and write to output file with replacements
with open(file_hdr_in, 'r') as fin:
   content = fin.read()
   
# Apply all replacements
for old, new in replacements.items():
   content = content.replace(old, new)
   
# Write modified content to output file
with open(file_hdr_out, 'w') as fout:
   fout.write(content)
