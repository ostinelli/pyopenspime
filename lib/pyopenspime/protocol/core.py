#
# PyOpenSpime - OpenSpime Protocol Core Module
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

"""OpenSpime Protocol Core Module."""

# imports
import pyopenspime.xmpp, pyopenspime.util


class Error(pyopenspime.xmpp.protocol.Iq):
    """
    PyOpenSpime Error stanza.
    """
    
    def __init__(self, stanza, error_type='modify', error_cond=None, error_namespace=None, error_description=None):  
        """
        Initialize an OpenSpime error stanza.
        
        @type  stanza: pyopenspime.xmpp.simplexml.Node
        @param stanza: The original stanza that the error is build for.
        @type  error_type: unicode
        @param error_type: The error type as defined by the XMPP protocol. Value MUST be 'cancel' -- do not retry
        (the error is unrecoverable), 'continue' -- proceed (the condition was only a warning), 'modify' -- retry
        after changing the data sent, 'auth' -- retry after providing credentials, 'wait' -- retry after waiting
        (the error is temporary). Defaults to I{modify}.
        @type  error_cond: unicode
        @param error_cond: The error condition.
        @type  error_namespace: unicode
        @param error_namespace: The error condition namespace.
        @type  error_description: unicode
        @param error_description: The error description.
        """
        
        # init component
        pyopenspime.xmpp.protocol.Iq.__init__(self, node=stanza)
        
        if error_cond <> None:
            
            # we are building a node
            
            # invert recipient and sender
            frm = self.getFrom()
            to = self.getTo()
            try: self.setTo(frm)
            except: pass
            try: self.setFrom(to)
            except: pass
            
            # ensure to have only an error reported, to avoid sending unencrypted data on the network -> empty all query
            self = pyopenspime.util.clean_node(self)
            
            # set 'error' type
            self.setType('error')
            
            # add error node <error type='modify'>
            n_error = self.addChild(name=u'error', attrs={u'type': error_type})
            
            # add bad-request as per xmpp protocol rfc 3920
            n_bad_request = n_error.addChild(name=u'bad-request')
            n_bad_request.setNamespace(u'urn:ietf:params:xml:ns:xmpp-stanzas')
            
            # add error_cond
            n_error_cond = n_error.addChild(name=unicode(error_cond))
            
            # add namespace
            if error_namespace <> None:
                n_error_cond.setNamespace(unicode(error_namespace))
            
            # add error description
            if error_description <> None:
                n_error_description = n_error.addChild(name=u'text', payload=unicode(error_description))
    
    def get_error(self):
        """
        Retrieves error condition and description from an error stanza.
        Reference is OpenSpime protocol Core Reference Schema v0.9.
        @rtype:   Dictionary
        @return:  Dictionary containing:
                                    error_cond
                                    error_description
        """
        
        # init
        error_cond = u''
        error_description = u''
        
        # seek error node
        n_error = pyopenspime.util.parse_all_children(self, 'error')
        
        for child in n_error.getChildren():
            if child.getName() == 'text':
                error_description = unicode(child.getData())
            else:
                error_cond = unicode(child.getName())

        return {"error_cond": error_cond, "error_description": error_description}


def wrap(transport_child_node, originator_osid=None, transport_to_osid=None):
    """
    Function that manages the OpenSpime Core Reference Schema. Used by extensions to build a complete <openspime/> node,
    before encryption and sign.
    
    Reference is OpenSpime protocol Core Reference Schema v0.9.
    
    @type  transport_child_node: pyopenspime.xmpp.simplexml.Node
    @type  originator_osid: unicode
    @param originator_osid: Sets 'osid' attribute of the <originator/> element. Defaults to I{None}.
    @type  transport_to_osid: unicode
    @param transport_to_osid: Sets 'to' attribute of the <transport/> element. Defaults to I{None}.
    @rtype:   pyopenspime.xmpp.simplexml.Node
    @return:  The <openspime/> node.
    """
    
    # create openspime root node
    n_openspime = pyopenspime.xmpp.simplexml.Node( tag='openspime', \
        attrs =  {u'xmlsn':u'openspime:protocol:core', u'version':u'0.9'} )
    
    # create <originator/> node
    n_originator = n_openspime.addChild(name='originator')
    if originator_osid <> None:
        n_originator.setAttr('osid', originator_osid)
    
    # create <transport/> node
    n_transport = n_openspime.addChild(name='transport')               
    if transport_to_osid <> None:
        n_transport.setAttr('to', transport_to_osid)
    
    # add child
    n_transport.addChild(node=transport_child_node)
    
    # return openspime node
    return n_openspime

