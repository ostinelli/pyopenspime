#
# PyOpenSpime - ScopeNode example, basic functionality
# version 0.1
# last update 2008 06 08
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

"""ScopeNode, basic code"""

###### Imports
import sys, os
os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))
sys.path.append('../lib') # use the local library
from pyopenspime.core import Client

###### PyOpenSpime
# Create new client -> bind log callback function
c = Client('scopenode@developer.openspime.com/testscope')
    
# Connect to OpenSpime SpimeGate
c.connect()

###### Callback function
def on_data_received(extname, extobj, stanza):
    if extname == 'datareporting':
        # ok data received send confirmation message
        print extobj.entries[0]
        c.send_stanza(extobj.accepted(), stanza.getFrom())
        """ example of a gone wrong report:

        c.send_stanza(extobj.error(error_type='modify', error_cond='inconsistent-data-with-scope', error_namespace='openspime:protocol:extension:data:error', \
                            error_description='Data is not consistent with scope of this ScopeNode.'), stanza.getFrom())
        """
c.on_data_received = on_data_received

###### Listening loop (server up)
try:
    while c.loop():
        pass
except KeyboardInterrupt:
    log.info(u'disconnecting and exiting')
    if c.isConnected == True:
        c.disconnect()
    exit(0)
except:
    log.error( "error (%s) while looping: %s" % (sys.exc_info()[0].__name__, sys.exc_info()[1]))
    exit(2)


