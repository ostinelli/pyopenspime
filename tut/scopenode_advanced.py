#
# PyOpenSpime - ScopeNode example, normal threaded functionality
# version 0.2
# last update 2008 08 16
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

"""ScopeNode, normal code"""


###### Imports
import sys, os, re
os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))
sys.path.append('../lib') # use the local library
from pyopenspime.client import Client


class TheScopeNode(Client):
    """
    PyOpenSpime 0.2 Normal ScopeNode
    """
    
    def on_connect(self):
        """
        Called on connection.
        """
        print u"scopenode is connected!"
    
    def on_disconnect(self):
        """
        Called on disconnection.
        """
        print u"scopenode has been diconnected!"
    
    def on_extension_received(self, extname, extobj, stanza):
        """
        Called when an openspime extension request has been received.
        """
        if extname == 'core.datareporting':
            # data received
            self.log(10, u'data reporting message received, checking consistency')
            # loop data received
            for entry_n in extobj.entries:
                # check for conformity
                if self.node_check(entry_n) == False:
                    self.log(30, u'received an inconsistent data reporting message.')
                    if extobj.stanza_kind == 'iq':
                        # non conform, send error since the request was containted in an iq stanza 
                        self.log(30, u'received an inconsistent data reporting message, sending error')
                        self.send_stanza(extobj.error(error_type='modify', error_cond='inconsistent-data-with-scope', error_namespace='openspime:protocol:extension:data:error', \
                            error_description='Data is not consistent with scope of this ScopeNode.'), stanza.getFrom())
                    # extension has been treated, return True
                    return True
            # data ok
            self.log(20, u'data reporting message received')
            if extobj.stanza_kind == 'iq':
                # send confirmation since the request was containted in an iq stanza 
                self.send_stanza(extobj.accepted(), stanza.getFrom())
            # print on screen
            print "======== \/ RECEIVED DATA ========"
            for entry_n in extobj.entries:
                print entry_n
            print "======== /\ RECEIVED DATA ========"
            # extension has been treated, return True
            return True

    def node_check(self, n):
        """
        Called for every data entry on a data reporting message received.
        This is a very simple example that validates the date, latitude and longitude nodes of a received message.
        """
        c_date = 0
        c_lat = 0
        c_lon = 0
        stop = False
        if n.getName().strip().lower() == 'entry':
            # check nodes
            for n_root_child in n.getChildren():
                if n_root_child.getName() == 'date':
                    # check on date
                    p = re.compile('^(\d{4}((-)?(0[1-9]|1[0-2])((-)?(0[1-9]|[1-2][0-9]|3[0-1])(T(24:00(:00(\.[0]+)?)?|(([0-1][0-9]|2[0-3])(:)[0-5][0-9])((:)[0-5][0-9](\.[\d]+)?)?).*)?)?)?)$')
                    m = p.match(n_root_child.getData())
                    if not m:
                        stop = True
                    else:
                        c_date += 1 # ok
                if n_root_child.getName() == 'lat':
                    # check on latitude
                    try:
                        lat = float(n_root_child.getData())
                        if lat < -90 or 90 < lat:
                            stop = True
                        else:
                            c_lat += 1 # ok
                    except:
                        stop = True
                if n_root_child.getName() == 'lon':
                    # check on longitude
                    try:
                        lon = float(n_root_child.getData())
                        if lon < -180 or 180 < lon:
                            stop = True
                        else:
                            c_lon += 1 # ok
                    except:
                        stop = True
        if c_date == 1 and c_lat == 1 and c_lon == 1 and stop == False:
            return True
        return False


if __name__ == "__main__":
    ###### Logging
    import logging
    logging.basicConfig(level = 10, format='%(asctime)s %(levelname)s %(message)s')
    log = logging.getLogger("MyScopeNode")
    
    ###### OpenSpime
    c = TheScopeNode('dev-scopenode-2@developer.openspime.com/scope', log_callback_function = log.log)
    c.run();
    
