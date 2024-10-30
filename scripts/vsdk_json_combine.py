#!/usr/bin/env python3
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2020 RDK Management
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

import os, sys, json
import argparse

def process_cmd_line():
   parser = argparse.ArgumentParser()
   parser.add_argument('-i', '--input',  action='store',  help="Input json file", required=True)
   parser.add_argument('-o', '--output', action='store',  help="Output json file", required=True)
   parser.add_argument('-a', '--add',    action='append', help="Add the json to the output file")
   parser.add_argument('-s', '--sub',    action='append', help="Remove the json from the output file")
   
   return(parser.parse_args())

def main():
   args = process_cmd_line()
   
   print("Combine input <{}> output <{}>".format(args.input, args.output))
   
   #print("Current directory <{}>".format(os.getcwd()))
   
   if not os.path.isfile(args.input):
      print("json input file not found <{}>".format(args.input))
      sys.exit(1)
   
   # Parse input json
   json_out = json_load(args.input)
   
   if args.sub:
      for arg_sub in args.sub: # Subtract json objects
         if ':' in arg_sub:
            (file_sub, loc_sub) = arg_sub.split(':', 1)
         else:
            file_sub = arg_sub
            loc_sub  = None
         
         if not os.path.isfile(file_sub):
            print("Subtract <{}> - FILE NOT FOUND".format(file_sub))
         else:
            print("Sub object from {} in {}".format(file_sub, loc_sub))
            json_sub = json_load(file_sub)
            if loc_sub is None:
               json_out = json_prune(json_out, json_sub)
            else:
               json_out[loc_sub] = json_prune(json_out[loc_sub], json_sub)
   
   if args.add:
      for arg_add in args.add: # Add json objects
         if ':' in arg_add:
            (file_add, loc_add) = arg_add.split(':', 1)
         else:
            file_add = arg_add
            loc_add  = None
         print("Add <{}>".format(file_add))
         if not os.path.isfile(file_add):
            print("Add <{}> - FILE NOT FOUND".format(file_add))
         else:
            print("Add object from {} in {}".format(file_add, loc_add))
            json_add = json_load(file_add)
            if loc_add is None:
               json_out = json_merge(json_out, json_add)
            else:
               if ',' not in loc_add:
                  if loc_add in json_out:
                     json_out[loc_add] = json_merge(json_out[loc_add], json_add)
                  else:
                     json_out[loc_add] = json_add
               else:
                  obj_names = loc_add.split(',')
                  obj_name_qty = len(obj_names)
                  if obj_name_qty == 2:
                     json_out[obj_names[0]][obj_names[1]] = json_merge(json_out[obj_names[0]][obj_names[1]], json_add)
                  elif obj_name_qty == 3:
                     json_out[obj_names[0]][obj_names[1]][obj_names[2]] = json_merge(json_out[obj_names[0]][obj_names[1]][obj_names[1]], json_add)
                  else:
                     raise TypeError('Too many object levels specified <{}>'.format(len(obj_names)))
   
   print("Write output to <{}>".format(args.output))
   json_dump(args.output, json_out)
   sys.exit(0)

def json_load(filename):
   with open(filename, 'r') as f:
      data = json.load(f)
   return data

def json_dump(filename, data):
   with open(filename, 'w') as f:
      json.dump(data, f, indent = 4)

def json_merge(json_in, json_add):
   json_out = json_in.copy()
   for key in json_add:
      if key in json_out and isinstance(json_out[key], dict) and isinstance(json_add[key], dict):
         json_out[key] = json_merge(json_out[key], json_add[key])
      elif key in json_out and isinstance(json_out[key], list) and isinstance(json_add[key], list):
         json_out[key] = json_out[key] + json_add[key]
      else:
         json_out[key] = json_add[key]
   
   return json_out

def json_prune(json_in, json_sub):
   json_out = json_in.copy()
   for key in json_sub.keys():
      if isinstance(json_out[key], dict) and isinstance(json_sub[key], dict):
         if len(json_sub[key]) == 0:
            del json_out[key]
         else:
            json_out[key] = json_prune(json_out[key], json_sub[key])
      else:
         del json_out[key]
      
   return json_out

if __name__ == "__main__":
   try:
      main()
   except Exception as e:
      print(e)
      sys.exit(1)
