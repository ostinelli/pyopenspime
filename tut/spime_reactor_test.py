#
# PyOpenSpime - Spime example, normal functionality
# version 0.2
# last update 2008 08 04
#
# Copyright (C) 2008, licensed under GPL v3
# Roberto Ostinelli <roberto AT openspime DOT com>
# Davide 'Folletto' Casali <folletto AT gmail DOT com>
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3 as published by
# the Free Software Foundation.
#
# You should have received a copy of the GNU General Public License v3
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
# 
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING, WITHOUT LIMITATION,
# ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY,
# OR FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT SHALL WIDETAG INC OR THE
# AUTHORS OF THIS SOFTWARE BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING
# FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE IMPLEMENTATION,
# DEPLOYMENT, OR OTHER USE OF THE SOFTWARE.
#
# IN NO EVENT AND UNDER NO LEGAL THEORY, WHETHER IN TORT (INCLUDING
# NEGLIGENCE), CONTRACT, OR OTHERWISE, UNLESS REQUIRED BY APPLICABLE LAW
# (SUCH AS DELIBERATE AND GROSSLY NEGLIGENT ACTS) OR AGREED TO IN WRITING,
# SHALL WIDETAG INC OR ANY AUTHOR OF THIS SOFTWARE BE LIABLE FOR DAMAGES,
# INCLUDING ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL
# DAMAGES OF ANY CHARACTER ARISING OUT OF THE USE OR INABILITY TO USE THE
# SOFTWARE (INCLUDING BUT NOT LIMITED TO DAMAGES FOR LOSS OF GOODWILL, WORK
# STOPPAGE, COMPUTER FAILURE OR MALFUNCTION, OR ANY AND ALL OTHER COMMERCIAL
# DAMAGES OR LOSSES), EVEN IF WIDETAG INC OR SUCH AUTHOR HAS BEEN ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGES.

"""Spime, normal code"""


###### Imports
import sys, os

os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))
sys.path.append('../lib') # use the local library
from pyopenspime.core import Client


class TheSpime(Client):
    """
    PyOpenSpime 0.2 Basic Spime
    """
    
    def connectionMade(self):
        """
        When connected, talks to the scopenode.
        """
        print u"Spime <%s> is online." % self.osid
        
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
        
        self.send_stanza(iq, 'dev-scopenode-3@developer.openspime.com/scope')#'scopenode@developer.openspime.com/scope')
        print u"Data '%s' sent." % iq
        #self.transport.write(iq, 'scopenode@developer.openspime.com/scope')
    
    def connectionLost(self):
        print u"Connection lost"
    
    def dataReceived(self, extname, extobj, stanza):
        print u"data with id '%s' succesfully received by recipient." % stanza.getID()
        #self.transport.loseConnection()

class TheScopeNode(Client):
    """
    PyOpenSpime 0.2 Basic ScopeNode
    """
    
    def connectionMade(self):
        print u"ScopeNode <%s> is online." % self.osid
    
    def connectionLost(self):
        print u"Connection lost."
    
    def dataReceived(self, extname, extobj, stanza):
        print u"Data received."
        if extname == 'datareporting':
            # ok data received send confirmation message
            print extobj.entries[0]
            self.send_stanza(extobj.accepted(), stanza.getFrom())
            """ example of a gone wrong report:

            c.send_stanza(extobj.error(error_type='modify', error_cond='inconsistent-data-with-scope', error_namespace='openspime:protocol:extension:data:error', \
                                error_description='Data is not consistent with scope of this ScopeNode.'), stanza.getFrom())
            """
        #self.transport.loseConnection()

if __name__ == "__main__":
    ###### Logging
    import logging
    logging.basicConfig(level = 10, format='%(asctime)s %(levelname)s %(message)s')
    log = logging.getLogger("MyScopeNode")
    
    ###### OpenSpime
    #c = TheSpime('dev-spime-3@developer.openspime.com/spime')
    c = TheScopeNode('dev-scopenode-3@developer.openspime.com/scope')
    c.on_log = log.log
    c.run();