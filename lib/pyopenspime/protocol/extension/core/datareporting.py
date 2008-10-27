#
# PyOpenSpime - Data Reporting Extension
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

"""Module that manages the OpenSpime Data Reporting protocol extension."""

# imports
from pyopenspime.xmpp.protocol import Iq, Message
from pyopenspime.xmpp.simplexml import Node
from pyopenspime.protocol.core import wrap, Error
import pyopenspime.util


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
        if stanza_type <> 'set':
            return False
    
    if stanza_kind == 'iq' or stanza_kind == 'message':
        for n_root_child in stanza.getChildren():
            if n_root_child.getName() == 'openspime':
                for n_os_child in n_root_child.getChildren():
                    if n_os_child.getName() == 'transport':
                        for n_transport_child in n_os_child.getChildren():
                            if n_transport_child.getName() == 'data':
                                return True
                                break
                        break
                break
    return False

def main(stanza, stanza_interpreter):        
    """
    Function called by StanzaInterpreter when stanza is to be handled by this extension.

    @type  stanza: pyopenspime.xmpp.protocol.Protocol
    @param stanza: Incoming stanza.

    @rtype:   pyopenspime.protocol.extension.core.datareporting.ReqObj()
    @return:  Extension's ReqObj.
    """
    
    # get stanza kind: iq, message, presence
    stanza_kind = stanza.getName().strip().lower()

    # create ReqObj
    reqobj = ReqObj(stanza_kind)
        
    # save stanza
    reqobj.stanza = stanza
    
    # get entries
    try:
        for n_root_child in stanza.getChildren():
            if n_root_child.getName() == 'openspime':
                for n_os_child in n_root_child.getChildren():
                    if n_os_child.getName() == 'transport':
                        for n_transport_child in n_os_child.getChildren():
                            if n_transport_child.getName() == 'data':
                                for n_entry in n_transport_child.getChildren():
                                    if n_entry.getName() == 'entry':
                                        reqobj.add_entry(n_entry)
                                break
                        break
                break
    except:
        pass
    return reqobj


class ReqObj():
    """Data Reporting Extension Request object."""
    
    def __init__(self, kind=None):        
        """
        Initialize a Data Reporting Extension Request object.
        """

        # set extension name here, MUST correspond to the one activated in pyopenspime.protocol.extension.conf
        self.extname = 'core.datareporting'
        
        # init
        self.stanza = None
        self.entries = []
        if kind <> 'iq' and kind <> 'message':
            raise Exception, 'data reporting type not supported. currently supported: \'iq\' and \'message\'.'
        self.stanza_kind = kind


    def add_entry(self, entry_xml):        
        """
        Add a data entry node.

        @type  entry_xml: unicode
        @param entry_xml: XML unicode string containing data to be added.
        """

        self.entries.append(Node(node=entry_xml))        


    def build(self):        
        """
        Builds the <transport/> node content of the data reporting stanza.
         
        @rtype:   pyopenspime.xmpp.simplexml.Node
        @return:  The <transport/> node content typical to the extension.
        """

        # empty existing stanza
        self.stanza = ''
        
        # build <data/> node, children of transport node - unique for extension
        n_data = Node( tag=u'data', \
            attrs =  {u'xmlsn':u'openspime:protocol:extension:data', u'version':u'0.9'} )
        
        # add entries
        for entry in self.entries:
            n_data.addChild(node=entry)

        # wrap data node in openspime protocol
        n_openspime = wrap(n_data)

        if self.stanza_kind == 'iq':
            # create new Iq stanza
            stanza = Iq(typ='set')
            # serialize id
            stanza.setID(pyopenspime.util.generate_rnd_str(16))
            # adding <openspime/> node as first child of <iq/> or <message/> stanza
            stanza.addChild(node=n_openspime)
        if self.stanza_kind == 'message':
            # create new Message stanza
            stanza = Message()
            # serialize id
            stanza.setID(pyopenspime.util.generate_rnd_str(16))
            # adding <openspime/> node as first child of <iq/> or <message/> stanza
            stanza.addChild(node=n_openspime)
        self.stanza = stanza
        # return
        return stanza

    
    def accepted(self):        
        """
        Builds a 'succefully received' stanza according to the OpenSpime Data Reporting protocol extension.

        @rtype:   pyopenspime.xmpp.protocol.Iq
        @return:  The Iq stanza to be sent out as confirmation message.
        """
        
        # prepare empty iq of type "result"
        if self.stanza_kind <> 'iq':
            return
        iq_ok = self.stanza.buildReply('result')
        return iq_ok


    def error(self, error_num):        
        """
        Builds a 'error' stanza according to the OpenSpime Data Reporting protocol extension.

        @type  error_num: int
        @param error_num: The error number of the response. Currently supported:
            * 1    : <inconsistent-data-with-scope/>, Data is not consistent with scope of this ScopeNode.

        @rtype:   pyopenspime.xmpp.protocol.Stanza
        @return:  The stanza to be sent out as error message.
        """
            
        if error_num == 1:
            stanza = Error(self.stanza, error_type='modify', error_cond='inconsistent-data-with-scope', error_namespace='openspime:protocol:extension:data:error', \
                         error_description='Data is not consistent with scope of this ScopeNode.') 
     
        return stanza
    

    def on_success(self, stanza):
        """
        If defined, event is called upon successful response to done request. Must return True if the client event on_response_success should be fired.
        """
        return True
    

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
        






