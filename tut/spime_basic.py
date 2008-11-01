#
# PyOpenSpime - Spime, basic example code.
# version 0.2
#
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

"""Spime, basic code."""

###### Set paths and imports
def add_to_sys_path(paths):
    for path in paths:
        if path not in sys.path:
            sys.path.append(path)
import sys, os
os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))
add_to_sys_path( ('lib',) )
from pyopenspime.client import Client
import pyopenspime.protocol.extension.core.datareporting

class TheSpime(Client):
    """
    PyOpenSpime 0.2 Basic Spime.
    """
    
    def on_connect(self):
        """
        When connected, sends a data reporting message to a scopenode.
        """
        self.send_data()

    def send_data(self):
        """
        Send a data reporting message using the OpenSpime data reporting core extension.
        """
        # create data reporting message which requests for confirmation (i.e. of type 'iq')
        dr_reqobj = pyopenspime.protocol.extension.core.datareporting.ReqObj('iq')

        # add xml data node
        dr_reqobj.add_entry(u"""<entry>
                <date>2008-10-09T10:02:22+01:00</date>
                <exposure>outdoor</exposure>
                <lat>45.475841199050905</lat>
                <lon>9.172725677490234</lon>
                <ele unit='m'>120.0</ele>
                <ppm>176.4</ppm>
            </entry>""")

        # send request
        req_id = self.send_request(dr_reqobj, 'dev-scopenode-2@developer.openspime.com/scope', encrypt = True, sign = True)

    def on_response_success(self, stanza_id, stanza):
        print "iq with id '%s' was successfully received by recipient." % stanza_id
        
    def on_response_failure(self, stanza_id, error_cond, error_description, stanza):
        print "error in sending iq with id '%s' [%s]: %s" % (stanza_id, error_cond, error_description)

    def on_response_timeout(self, stanza_id):
        print "timeout waiting for response to sent iq with id '%s'." % stanza_id
            
    

if __name__ == "__main__":
    ###### Logging
    import logging
    logging.basicConfig(level = 10, format='%(asctime)s %(levelname)s %(message)s')
    log = logging.getLogger("MySpime")
    
    ###### OpenSpime
    c = TheSpime('dev-spime-2@developer.openspime.com/spime', log_callback_function = log.log)
    c.run();

