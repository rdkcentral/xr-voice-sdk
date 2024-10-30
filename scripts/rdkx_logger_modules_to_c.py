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

file_json = sys.argv[1]
file_hash = sys.argv[2] + ".hash"
file_hdr  = sys.argv[2] + ".h"
file_c    = sys.argv[2] + "_lookup.c"

if not os.path.isfile(file_json):
   raise ValueError("The platform specific configuration file ({}) was not found. Please append the recipe for this platform and add the config file.".format(file_json))

# Parse the config file and generate rdkx_logger_module_hash.in
with open(file_json) as f:
   data = json.load(f)
   
# Make sure data is a dictionary with values equal to XLOG_LEVEL_*
if type(data) is not dict:
   raise ValueError("The platform specific configuration file ({}) parsing error - not a dictionary.".format(file_json))

f = open(file_hash, "w")

f.write("%language=ANSI-C\n")
f.write("%struct-type\n")
f.write("%includes\n")
f.write("%define lookup-function-name rdkx_logger_module_str_to_index\n")
f.write("%{\n")
f.write("#include \"rdkx_logger_private.h\"\n")
f.write("%}\n")
f.write("struct rdkx_logger_module_s;\n")
f.write("%%\n")

id = 0
values = ("XLOG_LEVEL_DEBUG", "XLOG_LEVEL_INFO", "XLOG_LEVEL_WARN", "XLOG_LEVEL_ERROR", "XLOG_LEVEL_FATAL")
for key in sorted(data):
   if data[key] not in values:
      raise ValueError("Platform specific configuration file ({}) parsing error - key {} has an invalid value {}.".format(file_json, key, data[key]))
   f.write("{0: <16} {1: >2}\n".format(key + ",", id))
   id += 1
f.write("%%")

fh = open(file_hdr, "w")

fh.write("#ifndef __RDKX_LOGGER_MODULES__\n")
fh.write("#define __RDKX_LOGGER_MODULES__\n")

# Enumeration
fh.write("\ntypedef enum {\n")
fh.write("   XLOG_MODULE_ID_NONE             = -1,\n")
id = 0
for key in sorted(data):
   fh.write("   XLOG_MODULE_ID_{0: <16} = {1: >2},\n".format(key,id))
   id += 1
fh.write("   XLOG_MODULE_ID_INVALID          = {0: >2}\n".format(id))
fh.write("} xlog_module_id_t;\n")
fh.write("\n#define XLOG_MODULE_QTY_MAX ({})\n\n".format(id))
fh.write("#endif\n")

# C file
fc = open(file_c, "w")
fc.write("const char * const g_xlog_module_id_to_str[{}] = {{\n".format(id))
id = 0
for key in sorted(data):
   fc.write("   \"{}\",\n".format(key))
   id += 1
fc.write("};\n")
fc.write("unsigned long g_xlog_module_id_to_strlen[{}] = {{\n".format(id))
id = 0
for key in sorted(data):
   fc.write("   {},\n".format(len(key)))
   id += 1
fc.write("};\n")
