#
# PyOpenSpime - Utility Functions
# version 1.0
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

"""PyOpenSpime generic utility functions."""

# imports
import random
import pyopenspime.xmpp.simplexml
from xml.dom import minidom
from xml.dom.ext import c14n


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












    
