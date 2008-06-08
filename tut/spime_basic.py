#
# PyOpenSpime - Spime example, basic functionality
# version 1.0
# last update 2008 06 07
#
# Copyright (C) 2008, licensed under GPL v2
# Roberto Ostinelli <roberto AT openspime DOT com>
# Davide 'Folletto' Casali <folletto AT gmail DOT com>
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Spime, basic code"""

# imports
import sys
#sys.path.append('../classes') # use the local library
from pyopenspime.core import Client

def log(level, msg):
    print('[%s] %s' % (level, msg))

#import logging
#logging.basicConfig(level = 10)
#log = logging.getLogger("MySpime").log

# create new client -> bind log callback function
c = Client('spime@developer.openspime.com/spime', log_callback_function=log)

# connect
c.connect()

# create data reporting message which requests for confirmation (i.e. of type 'iq')
import pyopenspime.extension.datareporting
dr = pyopenspime.extension.datareporting.ExtObj()

# add node
dr.add_entry(u"""<entry>
        <date>2008-04-02T17:54:22+01:00</date>
        <exposure>outdoor</exposure>
        <lat>45.475841199050905</lat>
        <lon>9.172725677490234</lon>
        <ele unit='m'>120.0</ele>
        <ppm>176.4</ppm>
    </entry>""")

# build message of kind 'iq', i.e. will wait for a confirmation or error message.
iq = dr.build('iq')

# define callbacks to data reporting
def Callback(stanza_id, stanza):
    print(u'data with id \'%s\' succesfully received by recipient.' % stanza_id)

# set handlers
c.set_iq_handlers(Callback)

# send
c.send_stanza(iq, 'scopenode@developer.openspime.com/testscope')



