#
# PyOpenSpime - Spime example, normal functionality
# version 0.1
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

"""Spime, normal code"""

###### Imports
import sys, os
os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))
sys.path.append('../lib') # use the local library
from pyopenspime.core import Client

###### Logging
import logging
logging.basicConfig(level = 10)
log = logging.getLogger("MySpime")

###### PyOpenSpime
# Create new client -> bind log callback function
c = Client(osid_or_osid_path = 'spime@developer.openspime.com/spime', log_callback_function = log.log)

# Connect to OpenSpime SpimeGate
try:
    c.connect()
except:
    log.error("error (%s) while connecting: %s" % (sys.exc_info()[0].__name__, sys.exc_info()[1]))
    exit(1)

###### Data
# Create data reporting message which requests for confirmation (i.e. of type 'iq')
import pyopenspime.extension.datareporting
dr = pyopenspime.extension.datareporting.ExtObj()

# Add node
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

###### Callback function
# define callbacks to data reporting
def on_success(stanza_id, stanza):
    log.info(u'data with id \'%s\' succesfully received by recipient.' % stanza_id)

def on_failure(stanza_id, error_cond, error_description, stanza):
    log.error(u"error (%s) on transmission of data with id \'%s\': %s" % (error_cond, stanza_id, error_description))

def on_timeout(stanza_id):
    log.error(u'timeout waiting confirmation for data with id \'%s\'.' % stanza_id)

# set handlers
c.set_iq_handlers(on_success, on_failure, on_timeout, 60)

###### Send
log.info(u'sending data reporting message with id \'%s\'' % iq.getID())
c.send_stanza(iq, 'scopenode@developer.openspime.com/testscope', encrypt = True, sign = True)
log.info(u'data reporting message queued for sending.')

###### Listening loop (client up)
try:
    while c.loop(1):
        pass
except KeyboardInterrupt:
    log.info(u'disconnecting and exiting')
    if c.isConnected == True:
        c.disconnect()
    exit(0)
except:
    log.error( "error (%s) while looping: %s" % (sys.exc_info()[0].__name__, sys.exc_info()[1]))
    exit(2)


