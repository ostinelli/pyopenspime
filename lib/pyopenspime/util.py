#
# PyOpenSpime - Utility Module
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

"""Utility Module."""

# imports
import random, time, os.path
import pyopenspime.xmpp.simplexml
from pyopenspime.xmpp.protocol import Protocol
from xml.dom import minidom
import c14n


def convert_client_type_to_name(typ):
        
    """Convert an OSclient type to a literal name.

    @type  typ: int
    @param typ: The OSclient type.

    @rtype:   unicode
    @return:  The literal name of the OSclient type (Spime, ScopeNode, Service)."""

    if osc_type == 0:
        return u"Spime"
    if osc_type == 1:
        return u"ScopeNode"
    if osc_type == 2:
        return u"Service"
    return u''

def to_utf8(s):
        
    """Convert a string to utf8.

    @type  s: str
    @param s: The string to be converted.
    
    @rtype:   utf-8 str
    @return:  The utf-8 converted string."""

    # Convevert `s` to UTF-8 if it is Unicode, leave unchanged if it is string or None and convert to string overwise
    if s is None:
        return None
    elif type(s) is unicode:
        return s.encode('utf-8')
    elif type(s) is str:
        return s
    else:
        return unicode(s).encode('utf-8')


def generate_rnd_str(str_len):    
        
    """Generates a random string.

    @type  str_len: int
    @param str_len: The lenght of the string.
    
    @rtype:   unicode
    @return:  The newly generated string."""

    # string elements
    items = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v', \
             'w','x','y','z','0','1','2','3','4','5','6','7','8','9']
    # init
    my_char = []
    for i in range(0, str_len):
        my_char.append(items[random.randint(0, len(items)-1)])
    return u''.join(my_char)

def parse_all_children(node, node_name, deep_first=False):
        
    """Recursively parses all children nodes of a node to find the first node that matches a name.

    @type  node: xmpp.simplexml.Node
    @param node: The node to parse.
    @type  node_name: unicode
    @param node_name: The node to find that matches this name.
    @type  deep_first: boolean
    @param deep_first: If set to True, searches into deep before passing to next child. If set to False, searches first
        children first before going deep. Defaults to I{False}.
    
    @rtype:   pyopenspime.xmpp.simplexml.Node
    @return:  The found node, or None if none found."""

    # get children
    children = node.getChildren()

    # if has children
    try:
        if len(children) > 0:
            if deep_first == False:
                for child in children:
                    if child.getName() == node_name:
                        # node found
                        return child
                for child in children:
                    # recursively call self
                    parse = parse_all_children(child, node_name, deep_first)
                    if parse <> None:
                        return parse
            else:
                for child in children:
                    if child.getName() == node_name:
                        # node found
                        return child
                    # recursively call self
                    parse = parse_all_children(child, node_name, deep_first)
                    if parse <> None:
                        return parse
    except:
        pass            
    return None


def clean_node(node):
        
    """Recursively deletes all content of a node.

    @type  node: xmpp.simplexml.Node
    @param node: The node to clean.
    
    @rtype:   xmpp.simplexml.Node
    @return:  The cleaned node."""

    for child in node.getChildren():
        node.delChild(child)
    node.clearData()
    return node


def convert_to_canonical_xml(xml):
        
    """Converts and XML string to the Canonical XML format as per W3C Canonical XML
    Version 1.0 <http://www.w3.org/TR/xml-c14n> specifications.

    @type  xml: unicode or str
    @param xml: The XML to be converted.
    
    @rtype:   unicode
    @return:  The canonical XML."""

    doc = minidom.parseString(pyopenspime.util.to_utf8(xml))
    return c14n.Canonicalize(doc)


def get_originator_osid(stanza):

    """Returns the originator OSID of an OpenSpime stanza, as specified in protocol v0.9.

    @type  stanza: xmpp.protocol.Protocol
    @param stanza: The full XMPP stanza.
    
    @rtype:   unicode
    @return:  The originator_osid."""

    # init
    originator_osid = None
    try:
        for n_root_child in stanza.getChildren():
            if n_root_child.getName() == 'openspime':
                for n_originator in n_root_child.getChildren():
                    if n_originator.getName() == 'originator':
                        if n_originator.getAttr('osid') <> None:
                            originator_osid = n_originator.getAttr('osid')
                        break
                break
    except:
        pass
    if originator_osid == None:
        originator_osid = str(stanza.getFrom())
    return originator_osid


def get_cert_osid(stanza):

    """Returns the certification authority OSID of an OpenSpime stanza, as specified in protocol v0.9.

    @type  stanza: xmpp.protocol.Protocol
    @param stanza: The full XMPP stanza.
    
    @rtype:   unicode
    @return:  The certification authority OSID."""

    # init
    cert_osid = None
    # get originator node
    n_originator = pyopenspime.util.parse_all_children(stanza, 'originator')
    if n_originator <> None:
        cert_osid = n_originator.getAttr('cert')
    return cert_osid


def iso_date_time(year=None, month=None, day=None, hour=None, minute=None, second=None):

    """Returns the current date and time in international standard ISO 8601.
    
    @type  year: int
    @param year: The year of the date. Defaults to the one of the current date.
    @type  month: int
    @param month: The month of the date. Defaults to the one of the current date.
    @type  day: int
    @param day: The day of the date. Defaults to the one of the current date.
    @type  hour: int
    @param hour: The hour of the date. Defaults to the one of the current date.
    @type  minute: int
    @param minute: The minute of the date. Defaults to the one of the current date.
    @type  second: int
    @param second: The second of the date. Defaults to the one of the current date.
    
    @rtype:   unicode
    @return:  The datetime string."""
    
    def str_min_len(str_num, str_len):
        while len(str_num) < str_len:
            str_num = "0%s" % str_num
        return str_num
    get_date = time.localtime()
    date = [get_date[0],get_date[1],get_date[2],get_date[3],get_date[4],get_date[5],get_date[6],get_date[7],get_date[8]]
    if year <> None: date[0] = year
    if month <> None: date[1] = month
    if day <> None: date[2] = day
    if hour <> None: date[3] = hour
    if minute <> None: date[4] = minute
    if second <> None: date[5] = second
    # get timezone
    if -time.timezone < 0:
        symbol = '-'
    else:
        symbol = '+'
    tz = "%s%s:%s" % ( symbol, str_min_len(str(int(-time.timezone / 3600)), 2), str_min_len(str(int((-time.timezone % 3600)/60)), 2) )
    # return format
    return "%s%s" % (time.strftime("%Y-%m-%dT%H:%M:%S", date), tz)


class OsPackage():
    """
    Class to manage OpenSpime packages. Currently performs read-only operations.
    """
    
    def __init__(self, osid_path, log_callback_function=None):
        """
        Initializes an OpenSpime package class.

        @type  osid_path: str
        @param osid_path: The full OSID of the client. If an OpenSpime configuration package is found, this is
            the only parameter that is needed to initialize the Client.            
        @type  log_callback_function: function
        @param log_callback_function: Callback function for logger. Function should accept two parameters: unicode
            (the log description) and integer (the verbosity level - 0 for error, 1 for warning, 2 for info,
            3 for debug).

        @rtype:   Dictionary
        @return:  Dictionary containing: osid_pass, server, port, cert_authority, rsa_pub_key_path, rsa_priv_key_path, rsa_priv_key_pass
        """
        
        # set log callback function
        if log_callback_function != None:
            self.log = log_callback_function
        # save
        self.osid_path = osid_path

    def read(self):
            
        # try to get openspime package     
        if os.path.isdir(self.osid_path) == True:
            try:
                # package found, read xml configuration
                self.log(10, 'openspime configuration package found, reading')
                f = open( "%s/conf.xml" % self.osid_path, "r" )
                n_conf = pyopenspime.xmpp.simplexml.Node(node=f.read())
                f.close()
                # init
                osid_pass = ''
                server = ''
                port = 0
                cert_authority = ''
                rsa_pub_key_path = ''
                rsa_priv_key_path = ''
                rsa_priv_key_pass = ''
                # get values
                self.log(10, 'getting values from package')
                try:
                    osid_pass = pyopenspime.util.parse_all_children(n_conf, 'osid-pass').getData()
                except:
                    self.log(10, 'could not get osid-pass from openspime configuration package.')
                try:
                    server = pyopenspime.util.parse_all_children(n_conf, 'server').getData()
                except:
                    self.log(10, 'could not get server from openspime configuration package.')
                try:
                    port = pyopenspime.util.parse_all_children(n_conf, 'port').getData()
                except:
                    self.log(10, 'could not get port from openspime configuration package.')
                try:
                    rsa_priv_key_pass = pyopenspime.util.parse_all_children(n_conf, 'rsa-priv-key-pass').getData()
                except:
                    self.log(10, 'could not get rsa-priv-key-pass from openspime configuration package.')
                try:
                    cert_authority = pyopenspime.util.parse_all_children(n_conf, 'cert-authority').getData()
                except:
                    self.log(10, 'could not get cert-authority from openspime configuration package.')
                rsa_pub_key_path = '%s/keys/public.pem' % self.osid_path
                if os.path.isfile(rsa_pub_key_path) == False:
                    rsa_pub_key_path = ""
                    self.log(30, 'could not find the rsa public key file.')
                rsa_priv_key_path = '%s/keys/private.pem' % self.osid_path
                if os.path.isfile(rsa_priv_key_path) == False:
                    rsa_priv_key_path = ""
                    self.log(30, 'could not find the rsa private key file.')
                # return
                output = {"osid_pass": osid_pass,
                           "server": server,
                           "port": port,
                           "cert_authority": cert_authority,
                           "rsa_pub_key_path": rsa_pub_key_path,
                           "rsa_priv_key_path": rsa_priv_key_path,
                           "rsa_priv_key_pass": rsa_priv_key_pass,
                    }
                return output
            except:
                msg = 'openspime configuration package is corrupted, aborting.'
                self.log(40, 'openspime configuration package is corrupted, aborting.')
                raise Exception, msg

        # no openspime package found
        return None
    

    def log(self, level, msg):
        """
        Logging function triggered on log messages.
        Uses the same syntax of logger.Logger.append()
        """
        pass


    
