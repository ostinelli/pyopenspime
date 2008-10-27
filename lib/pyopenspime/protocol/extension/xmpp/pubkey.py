#
# PyOpenSpime - PubKey XMPP Extension
# version 0.2
#
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

"""Module that manages the PubKey XMPP protocol extension."""

# imports
from pyopenspime.xmpp.protocol import Iq
from pyopenspime.xmpp.simplexml import Node
from pyopenspime.protocol.core import wrap, Error
import pyopenspime.util
import binascii
import M2Crypto.RSA


def validate(stanza, stanza_interpreter):        
    """
    Function called by StanzaInterpreter, used to determine if the incoming stanza is to be handled by this extension.

    @type  stanza: pyopenspime.xmpp.protocol.Protocol
    @param stanza: Incoming stanza.

    @rtype:   boolean
    @return:  True if stanza is to be handled by this extension, False otherwise.
    """

    # get stanza kind: iq, message, presence
    try: stanza_kind = stanza.getName().strip().lower()
    except: pass
    # get stanza type: get, set, result, error
    try: stanza_type = stanza.getType().lower()
    except: pass

    if stanza_kind == 'iq':
        # iq must be of type 'set'
        if stanza_type <> 'get':
            return False
        for n_root_child in stanza.getChildren():
            if n_root_child.getName() == 'pubkeys':
                return True
                break
    return False

def main(stanza, stanza_interpreter):        
    """
    Function called by StanzaInterpreter when stanza is to be handled by this extension.

    @type  stanza: pyopenspime.xmpp.protocol.Protocol
    @param stanza: Incoming stanza.

    @rtype:   pyopenspime.protocol.extension.xmpp.pubkey.ReqObj()
    @return:  Extension's ReqObj.
    """

    # get osid_pubkey    
    try:
        for n_root_child in stanza.getChildren():
            if n_root_child.getName() == 'pubkeys':
                osid_pubkey = n_root_child.getAttr('jid')
                break
    except:
        pass

    # create ReqObj
    reqobj = ReqObj(osid_pubkey)

    # save
    reqobj.stanza_interpreter = stanza_interpreter
    reqobj.stanza = stanza

    # return
    return reqobj


class ReqObj():
    """PubKey XMPP Extension Request object."""
    
    def __init__(self, osid_pubkey):        
        """
        Initialize a PubKey XMPP Extension Request object.
        """

        # set extension name here, MUST correspond to the one activated in pyopenspime.protocol.extension.conf
        self.extname = 'xmpp.pubkey'
        # init
        self.osid_pubkey = osid_pubkey
        self.stanza = None
        self.stanza_interpreter = None


    def build(self):   
        """
        Builds the <transport/> node content of the data reporting stanza.
         
        @rtype:   pyopenspime.xmpp.simplexml.Node
        @return:  The <transport/> node content typical to the extension.
        """
        
        # empty existing stanza
        self.stanza = ''
        
        # build <iq/> node
        pubkey_iq = pyopenspime.xmpp.protocol.Iq(typ='get')
        pubkey_iq.addChild(u'pubkeys', namespace=u'urn:xmpp:tmp:pubkey', \
                           attrs={ 'jid': self.osid_pubkey })
 
        self.stanza = pubkey_iq
        # return
        return pubkey_iq

    
    def accepted(self):        
        """
        Builds a response stanza to the PubKey request received

        @rtype:   pyopenspime.xmpp.protocol.Iq
        @return:  The Iq stanza to be sent out as confirmation message.
        """

        if self.stanza_interpreter.osid == self.osid_pubkey:
            if self.stanza_interpreter.endec.rsa_pub_key <> None:
                # ok prepare response
                self.stanza_interpreter.log(10, u'request pubkey received, send public key')
                pubkey_iq = pyopenspime.xmpp.protocol.Iq(typ='result')
                n_pubkey = pubkey_iq.addChild(u'pubkeys', namespace=u'urn:xmpp:tmp:pubkey', attrs={ u'jid': self.osid_pubkey })
                n_KeyInfo = n_pubkey.addChild(u'KeyInfo', namespace=u'http://www.w3.org/2000/09/xmldsig#')
                n_RSAKeyValue = n_KeyInfo.addChild(u'RSAKeyValue')
                n_Modulus = n_RSAKeyValue.addChild(u'Modulus')
                n_Modulus.setData(binascii.b2a_base64(self.stanza_interpreter.endec.rsa_pub_key.n).replace('\r','').replace('\n',''))
                n_Exponent = n_RSAKeyValue.addChild(u'Exponent')
                n_Exponent.setData(binascii.b2a_base64(self.stanza_interpreter.endec.rsa_pub_key.e).replace('\r','').replace('\n',''))                   
            else:
                # ko prepare response no keys!
                self.stanza_interpreter.log(30, u'request pubkey received however no public RSA key has been specified, send error response.')
                # prepare response
                pubkey_iq = Error(self.stanza, 'cancel', 'no-available-public-key', 'openspime:protocol:core:error', \
                                'recipient has no available public key.')                
        else:
            self.stanza_interpreter.log(10, u'request for another entity, build error')
            # prepare response       
            pubkey_iq = Error(self.stanza, 'cancel', 'item-not-found', 'urn:ietf:params:xml:ns:xmpp-stanzas', \
                            'recipient has no available public key.')                
        
        # complete and return
        try: pubkey_iq.setTo(self.stanza.getFrom())
        except: pass
        try: pubkey_iq.setID(self.stanza.getID())
        except: pass
        return pubkey_iq


    def error(self, error_type, error_cond, error_namespace=None, error_description=None):        
        """
        Builds a 'error' stanza according to the OpenSpime Data Reporting protocol extension.

        @type  error_type: unicode
        @param error_type: The error type as defined by the XMPP protocol. Value MUST be 'cancel' -- do not retry
        (the error is unrecoverable), 'continue' -- proceed (the condition was only a warning), 'modify' -- retry
        after changing the data sent, 'auth' -- retry after providing credentials, 'wait' -- retry after waiting
        (the error is temporary).
        @type  error_cond: unicode
        @param error_cond: The error condition.
        @type  error_namespace: unicode
        @param error_namespace: The error condition namespace.
        @type  error_description: unicode
        @param error_description: The error description.

        @rtype:   pyopenspime.xmpp.protocol.Iq
        @return:  The Iq stanza to be sent out as error message.
        """
        
        # prepare empty iq of type "result"
        iq_ko = Error(self.stanza, error_type, error_cond, error_namespace, error_description)        
        return iq_ko
    

    def on_success(self, stanza):
        """
        If defined, event is called upon successful response to done request. Must return True if the client event on_response_success should be fired.
        """

        # key received, save key
        for child in stanza.getChildren():
            if child.getName() == 'pubkeys':
                # get osid of key owner
                osid_key_owner = child.getAttr('jid')
                # get values
                n_RSAKeyValue = pyopenspime.util.parse_all_children(child, 'RSAKeyValue', True)
                n_Modulus = pyopenspime.util.parse_all_children(n_RSAKeyValue, 'Modulus', True)
                n_Exponent = pyopenspime.util.parse_all_children(n_RSAKeyValue, 'Exponent', True)
                try:
                    # create key
                    new_pub_key = M2Crypto.RSA.new_pub_key((binascii.a2b_base64(n_Exponent.getData()), \
                                                            binascii.a2b_base64(n_Modulus.getData())))
                    # osid name
                    osid_key_owner_hex = binascii.b2a_hex(osid_key_owner)
                    osid_key_owner_key_path = '%s/%s' % (self.stanza_interpreter.rsa_key_cache_path, osid_key_owner_hex)
                    originator_osid = pyopenspime.util.get_originator_osid(stanza)
                    if originator_osid <> '':
                        if osid_key_owner <> originator_osid:
                            # it's a request to a third party, check if in accepted_cert_authorities [i.e. if it's an authority]
                            if originator_osid in self.stanza_interpreter.accepted_cert_authorities:
                                # coming from a cert authority, add the .fromcert extension to file
                                osid_key_owner_key_path = '%s.fromcert' % osid_key_owner_key_path
                    # save key
                    new_pub_key.save_pub_key(osid_key_owner_key_path)
                    self.stanza_interpreter.log(10, u'a new public key has been received and successfully saved into the cache directory.')
                except:
                    self.stanza_interpreter.log(10, u'a new public key has been received, but there was an error in saving the key to cache directory.')
        return False
    

    def on_failure(self, stanza):
        """
        If defined, event is called upon failure response to done request. Must return True if the client event on_response_failure should be fired.
        """
        return True
    

    def on_timeout(self, stanza_id):
        """
        If defined, event is called upon timeout waiting response for done request. Must return True if the client event on_response_timeout should be fired.
        """
        return True
        








