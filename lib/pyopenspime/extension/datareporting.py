#
# PyOpenSpime - Data Reporting Extension
# version 0.1
# last update 2008 06 07
#
# Copyright (C) 2008, licensed under GPL v2
# Roberto Ostinelli <roberto AT openspime DOT com>
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

"""Module that manages the OpenSpime Data Reporting protocol extension.

Reference is OpenSpime Data Reporting protocol extension v0.9."""

# imports
from pyopenspime.xmpp.protocol import Iq, Message
from pyopenspime.xmpp.simplexml import Node
from pyopenspime.core import wrap, Error
import pyopenspime.util


def validate(stanza):
        
    """Function called by StanzaHandler, used to determine if the incoming stanza is to be handled by this extension.

    @type  stanza: pyopenspime.xmpp.protocol.Protocol
    @param stanza: Incoming stanza."""

    stanza_type = stanza.getName().strip().lower()

    if stanza_type == 'iq' or stanza_type == 'message':
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

def main(stanza):
        
    """Function called by StanzaHandler when stanza is to be handled by this extension.

    @type  stanza: pyopenspime.xmpp.protocol.Protocol
    @param stanza: Incoming stanza."""
    
    # get stanza kind: iq, message, presence
    stanza_kind = stanza.getName().strip().lower()

    # create ExtObj
    extobj = ExtObj()
        
    # save stanza & kind
    extobj._incomed_stanza = stanza
    extobj._kind = stanza_kind
    
    # get stanza type: set, get, result, error
    stanza_type = stanza.getType()
    # dispatch
    if stanza_kind == 'message' or (stanza_kind == 'iq' and stanza_type == 'set'):
        # reset
        extobj.entries = []
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
                                            extobj.add_entry(n_entry)
                                    break
                            break
                    break
        except:
            pass
    return extobj

class ExtObj():

    """Data Reporting Extension object."""
    
    def __init__(self):
        
        """Initialize an ExtObj Data Reporting extension object."""
        
        # init
        self.entries = []
        self._incomed_stanza = None
        self._kind = None

    def add_entry(self, entry_xml):
        
        """Add a data entry node.

        @type  entry_xml: unicode
        @param entry_xml: XML unicode string containing data to be added."""

        self.entries.append(Node(node=entry_xml))        

    def build(self, kind):
        
        """Builds the <transport/> node content.

        @type  kind: unicode
        @param kind: Must be I{iq}, I{message} or I{pubsub}. PubSub is not supported by this PyOS version.

        @rtype:   pyopenspime.xmpp.simplexml.Node
        @return:  The stanza to be sent out."""

        if kind <> 'iq' and kind <> 'message':
            raise Exception, 'data reporting type not supported. currently supported: \'iq\' and \'message\'.'

        # build <data/> node, children of transport node - unique for extension
        n_data = Node( tag=u'data', \
            attrs =  {u'xmlsn':u'openspime:protocol:extension:data', u'version':u'0.9'} )
        
        # add entries
        for entry in self.entries:
            n_data.addChild(node=entry)

        # wrap data node in openspime protocol
        n_openspime = wrap(n_data)

        if kind == 'iq':
            # create new Iq stanza
            stanza = Iq(typ='set')
            # serialize id
            stanza.setID(pyopenspime.util.generate_rnd_str(16))
            # adding <openspime/> node as first child of <iq/> or <message/> stanza
            stanza.addChild(node=n_openspime)
        if kind == 'message':
            # create new Message stanza
            stanza = Message()
            # serialize id
            stanza.setID(pyopenspime.util.generate_rnd_str(16))
            # adding <openspime/> node as first child of <iq/> or <message/> stanza
            stanza.addChild(node=n_openspime)

        # return
        return stanza

    def accepted(self):
        
        """Builds a 'succefully received' stanza according to the OpenSpime Data Reporting protocol extension.

        @rtype:   pyopenspime.xmpp.protocol.Iq
        @return:  The Iq stanza to be sent out as confirmation message."""
        
        # prepare empty iq of type "result"
        if self._kind <> 'iq':
            raise Exception, '\'accepted\' responses can only be build for \'iq\' type of data reporting.'
        iq_ok = self._incomed_stanza.buildReply('result')
        return iq_ok

    def error(self, error_type, error_cond, error_namespace=None, error_description=None):
        
        """Builds a 'error' stanza according to the OpenSpime Data Reporting protocol extension.

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
        @return:  The Iq stanza to be sent out as error message."""
        
        # prepare empty iq of type "result"
        if self._kind <> 'iq':
            raise Exception, '\'error\' responses can only be build for \'iq\' type of data reporting.'
        iq_ko = Error(self._incomed_stanza, error_type, error_cond, error_namespace, error_description)        
        return iq_ko




        








