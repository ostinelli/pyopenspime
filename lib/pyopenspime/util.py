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
import random, time
import pyopenspime.xmpp.simplexml
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



    
