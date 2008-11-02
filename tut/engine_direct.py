#
# PyOpenSpime - OpenSpime protocol engine example code.
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


"""OpenSpime protocol engine."""


#################
# Configuration #
#################

# OSID
OSID = 'dev-spime-2@developer.openspime.com/spime'

#################



###### Set paths and imports
def add_to_sys_path(paths):
    for path in paths:
        if path not in sys.path:
            sys.path.append(path)
import sys, os
os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))
add_to_sys_path( ('lib',) )
import logging, pyopenspime.xmpp.protocol, pyopenspime.protocol.extension.core.datareporting, pyopenspime.protocol.extension.xmpp.pubkey
from pyopenspime.engine import StanzaInterpreter



class TheStanzaInterpreter(StanzaInterpreter):
    """
    PyOpenSpime 0.2 Stanza Interpreter.
    """
    
    def run_examples(self):
        """
        Creates sequentially 2 extension stanzas and interpret them. Display results on screen.
        """        

        ### create new datareporting and print request on screen

        new_datareporting_stanza = self.datareporting_create()
        print '\n============== \/ DATA REPORTING ==============\n\nrequest to be sent out:\n\n%s\n\n' % new_datareporting_stanza
        
        # feed stanza interpreter with newly created datareporting and let it interpret it, raise errors if any
        handler = self.validate(new_datareporting_stanza)
        # dispatch 
        if isinstance(handler, pyopenspime.xmpp.protocol.Protocol) == True:
            # errors found, print on screen the response stanza
            reponse_stanza = handler
            print '\n\nerrors found in incoming request, stanza to be sent out is:\n\n%s\n\n' % reponse_stanza
        if hasattr(handler, 'extname') == True:
            reqobj = handler
            if reqobj.extname == 'core.datareporting':
                print '\n\ndatareporting stanza received contains the following entries:\n\n'
                for entry_n in reqobj.entries:
                    print '%s\n\n' % entry_n
                print '\nstanza to be sent out as confirmation is:\n\n%s\n\n' % str(reqobj.accepted())
        print '============== /\ DATA REPORTING ==============\n\n'

        ### create new public key request and print request on screen

        new_pubkey_stanza = self.pubkey_create()
        print '\n============== \/ PUBLIC KEY ==============\n\nrequest to be sent out:\n\n%s\n\n' % new_pubkey_stanza

        # feed stanza interpreter with newly created datareporting and let it interpret it, raise errors if any
        handler = self.validate(new_pubkey_stanza)
        # dispatch 
        if isinstance(handler, pyopenspime.xmpp.protocol.Protocol) == True:
            # errors found, print on screen the response stanza
            reponse_stanza = handler
            print '\n\nerrors found in incoming request, stanza to be sent out is:\n\n%s\n\n' % reponse_stanza
        if hasattr(handler, 'extname') == True:
            reqobj = handler
            if reqobj.extname == 'xmpp.pubkey':
                # response raises error. this is because we have build a request for 
                print '\nstanza to be sent out as response is:\n\n%s\n\n' % str(reqobj.accepted())
        print '============== /\ PUBLIC KEY ==============\n\n'
        

    def datareporting_create(self):
        """
        Creates a new data reporting stanza.
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
        
        # create request
        stanza_request = dr_reqobj.build()
        # encrypt and sign the request.
        # N.B.: you need to have the recipient public rsa key to encrypt, and the sender's private rsa key
        # to sign an outgoing stanza, otherwise errors will be raised.
        # in this example, no encryption and no signature are performed.
        stanza_request = self.encrypt_and_sign(stanza_request, encrypt=False, sign=False)
        # return
        return stanza_request


    def pubkey_create(self):
        """
        Creates a new public key request stanza.
        """
        
        ### create new public key request and print request on screen
        
        pubkey_reqobj = pyopenspime.protocol.extension.xmpp.pubkey.ReqObj('dev-spime-2@developer.openspime.com/spime')
        # create request
        stanza_request = pubkey_reqobj.build()
        # encrypt and sign the request.
        # N.B.: you need to have the recipient public rsa key to encrypt, and the sender's private rsa key
        # to sign an outgoing stanza, otherwise errors will be raised.
        # in this example, no encryption and no signature are performed.
        stanza_request = self.encrypt_and_sign(stanza_request, encrypt=False, sign=False)
        # return
        return stanza_request



###### START application
if __name__ == "__main__":
    
    ### Logging
    logging.basicConfig(level = 10, format='%(asctime)s %(levelname)s %(message)s')
    log = logging.getLogger("Engine [%s]" % OSID)
    
    ### Engine
    si = TheStanzaInterpreter(OSID, log_callback_function = log.log)

    ### run examples and print results to screen
    si.run_examples()

