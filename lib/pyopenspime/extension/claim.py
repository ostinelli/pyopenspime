#
# PyOpenSpime - Claim Extension
# version 0.1
# last update 2008 08 18
#
# Copyright (C) 2008, licensed under GPL v3
# Roberto Ostinelli <roberto AT openspime DOT com>
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

"""Module that manages the OpenSpime Data Reporting protocol extension.

Reference is OpenSpime Data Reporting protocol extension v0.9."""

# imports
import time
from pyopenspime.xmpp.protocol import Iq
from pyopenspime.xmpp.simplexml import Node
from pyopenspime.core import wrap, Error
import pyopenspime.util


def validate(stanza):
        
    """Function called by StanzaHandler, used to determine if the incoming stanza is to be handled by this extension.

    @type  stanza: pyopenspime.xmpp.protocol.Protocol
    @param stanza: Incoming stanza."""

    stanza_kind = stanza.getName().strip().lower()

    if stanza_kind == 'iq':
        for n_root_child in stanza.getChildren():
            if n_root_child.getName() == 'openspime':
                for n_os_child in n_root_child.getChildren():
                    if n_os_child.getName() == 'transport':
                        for n_transport_child in n_os_child.getChildren():
                            if n_transport_child.getName() == 'claim':
                                return True
                                break
                        break
                break
    return False

def main(stanza, client):
        
    """Function called by StanzaHandler when stanza is to be handled by this extension.

    @type  stanza: pyopenspime.xmpp.protocol.Protocol
    @param stanza: Incoming stanza."""

    # get stanza kind: iq, message
    stanza_kind = stanza.getName().strip().lower()

    # create ExtObj
    extobj = ExtObj()
        
    # save stanza & kind
    extobj._incomed_stanza = stanza
    extobj._client = client
    
    # get stanza type: set, get, result, error
    stanza_type = stanza.getType()
    # dispatch
    if stanza_kind == 'iq' and stanza_type == 'set':
        # get request
        try:
            for n_root_child in stanza.getChildren():
                if n_root_child.getName() == 'openspime':
                    for n_os_child in n_root_child.getChildren():
                        if n_os_child.getName() == 'transport':
                            for n_transport_child in n_os_child.getChildren():
                                if n_transport_child.getName() == 'claim':
                                    for n_request in n_transport_child.getChildren():
                                        if n_request.getName() == 'request':
                                            # get requested osid
                                            requested_osid = n_request.getAttr('claims')
                                            # save data in extobj
                                            extobj.type = 'request'
                                            extobj.originator_osid = pyopenspime.util.get_originator_osid(stanza)
                                            extobj.requested_osid = requested_osid
                                            break
                                    break
                            break
                    break
        except:
            pass

            pass
    return extobj

class ExtObj():

    """Data Reporting Extension object."""
    
    def __init__(self):
        
        """Initialize an ExtObj Data Reporting extension object."""
        
        # init
        self.originator_osid = None
        self.requested_osid = None
        self.type = None
        self._incomed_stanza = None
        self._client = None
        
    def build(self, osid):
        
        """Builds <transport/> node content of the claim request.

        @type  osid: unicode
        @param osid: The full OSID of the entity from which we are asking a claim key.

        @rtype:   pyopenspime.xmpp.simplexml.Node
        @return:  The stanza to be sent out."""

        # set type
        self.type = 'request'
    
        # build <claim/> node, children of transport node - unique for extension
        n_claim = Node( tag=u'claim', \
            attrs = {u'xmlsn':u'openspime:protocol:extension:claim', u'version':u'0.9'} )

        # add request node
        n_request = n_claim.addChild(name=u'request', attrs={u'claims': osid})

        # wrap data node in openspime protocol
        n_openspime = wrap(n_claim)

        # create new Iq stanza
        stanza = Iq(typ='set')
        # serialize id
        stanza.setID(pyopenspime.util.generate_rnd_str(16))
        # adding <openspime/> node as first child of <iq/> stanza
        stanza.addChild(node=n_openspime)
        
        # return
        return stanza

    def accepted(self):
        
        """Builds a claim response message.

        @rtype:   pyopenspime.xmpp.protocol.Iq
        @return:  The Iq stanza to be sent out as confirmation message."""

        # set type
        self.type = 'response'
    
        # build <claim/> node, children of transport node - unique for extension
        n_claim = Node( tag=u'claim', \
            attrs = {u'xmlsn':u'openspime:protocol:extension:claim', u'version':u'0.9'} )

        # add response node
        n_response = n_claim.addChild(name=u'response', attrs={u'authorizes': self.originator_osid})

        # generate claim key
        claimkey = self.__generate_claimkey()
        
        # add claimkey
        n_claimkey = n_response.addChild(name=u'claimkey')
        n_claimkey.setData(claimkey)

        # wrap data node in openspime protocol
        n_openspime = wrap(n_claim)

        # build response
        iq_ok = self._incomed_stanza.buildReply('result')

        # adding <openspime/> node as first child of <iq/> stanza
        iq_ok.addChild(node=n_openspime)
        
        # return
        print iq_ok
        return iq_ok

    def __generate_claimkey(self):

        # generate a claim key

        # claimkey string, with expiration date to one year from now
        claimkey = "<claimkey xmlns='openspime:protocol:core:claimkey' version='0.9'><osid>%s</osid> \
                    <expdate>%s</expdate></claimkey>" % ( str(self.requested_osid), str(pyopenspime.util.iso_date_time(year=time.localtime()[0]+1)) )
        # return encoded claimkey with private RSA key of the claimed entity
        return self._client._endec.private_encrypt_text(claimkey).replace('\r', '').replace('\n', '')


        








        








