#
# PyOpenSpime - Core
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

"""PyOpensPime Core Module."""

import sys, locale, codecs, binascii, time, os.path, sha
import M2Crypto.RSA
import M2Crypto.EVP
import M2Crypto.BIO
import pyopenspime.xmpp
import pyopenspime.util
from pyopenspime.conf.settings import *


class Client(pyopenspime.xmpp.Client):
    """PyOpensPime XMPP Client."""
    
    def __init__(self, osid_or_osid_path, osid_pass='', server='', port=5222, rsa_pub_key_path='', rsa_priv_key_path='', rsa_priv_key_pass='', rsa_key_cache_path='cache', cert_authority='', accepted_cert_authorities_filepath='certification-authorities.conf', try_reconnect=60, log_callback_function=None):
        
        """Initialize a Client.
        @type  osid_or_osid_path: str
        @param osid_or_osid_path: The full OSID of the client. If an OpenSpime configuration package is found, this is
            the only parameter that is needed to initialize the Client.
        @type  osid_pass: str
        @param osid_pass: The full OSID password. I{Taken from the OpenSpime configuration package if found}.
        @type  server: str
        @param server: The server address. Defaults to the OSID domain.
        @type  port: int
        @param port: The server port. Defaults to I{5222}.
        @type  rsa_pub_key_path: unicode
        @param rsa_pub_key_path: The path to the RSA public key .pem file. I{Taken from the OpenSpime configuration
            package if found}.
        @type  rsa_priv_key_path: unicode
        @param rsa_priv_key_path: The path to the RSA private key .pem file. I{Taken from the OpenSpime configuration
            package if found}.
        @type  rsa_priv_key_pass: unicode
        @param rsa_priv_key_pass: The RSA private key .pem file password. I{Taken from the OpenSpime configuration
            package if found}.
        @type  rsa_key_cache_path: unicode
        @param rsa_key_cache_path: The path to cached public RSA keys of entities. Defaults to I{/cache}.
        @type  cert_authority: unicode
        @param cert_authority: The client's certification authority. I{Taken from the OpenSpime configuration package
            if found}.
        @type  accepted_cert_authorities_filepath: unicode
        @param accepted_cert_authorities_filepath: The path to the file of accepted certification authorities. Defaults
            to file I{certification-authorities.conf} in root folder.
        @type  try_reconnect: int
        @param try_reconnect: Reconnects if connection drops. Set to 0 if no reconnect, otherwise integer expresses
            interval to reconnection trials in seconds. Defaults to I{60}.
        @type  log_callback_function: function
        @param log_callback_function: Callback function for logger. Function should accept two parameters: unicode
            (the log description) and integer (the verbosity level - 0 for error, 1 for warning, 2 for info,
            3 for debug)."""
        
        # XMPP protocol is unicode-based. convert output format to local encoding to avoid UnicodeException error.
        locale.setlocale(locale.LC_CTYPE,"")
        encoding = locale.getlocale()[1]
        if not encoding:
            encoding = "us-ascii"
        sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors = "replace")
        sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors = "replace")
        
        # set log callback function
        if log_callback_function == None:
            self.log = self.__on_log
        else:
            self.log = log_callback_function
        
        # try to get openspime package     
        if os.path.isdir(osid_or_osid_path) == True:
            try:
                # package found, read xml configuration
                self.log( 'openspime configuration package found, reading', 3)
                f = open( "%s/conf.xml" % osid_or_osid_path, "r" )
                n_conf = pyopenspime.xmpp.simplexml.Node(node=f.read())
                f.close()
                # get values
                c_osid_pass = None
                c_server = None
                c_port = None
                c_rsa_priv_key_pass = None
                c_cert_authority = None
                self.log( 'getting values from package', 3)
                try:
                    c_osid_pass = pyopenspime.util.parse_all_children(n_conf, 'osid-pass').getData()
                except:
                    self.log( 'could not get osid-pass from openspime configuration package.', 3)
                try:
                    c_server = pyopenspime.util.parse_all_children(n_conf, 'server').getData()
                except:
                    self.log( 'could not get server from openspime configuration package.', 3)
                try:
                    c_port = pyopenspime.util.parse_all_children(n_conf, 'port').getData()
                except:
                    self.log( 'could not get port from openspime configuration package.', 3)
                try:
                    c_rsa_priv_key_pass = pyopenspime.util.parse_all_children(n_conf, 'rsa-priv-key-pass').getData()
                except:
                    self.log( 'could not get rsa-priv-key-pass from openspime configuration package.', 3)
                try:
                    c_cert_authority = pyopenspime.util.parse_all_children(n_conf, 'cert-authority').getData()
                except:
                    self.log( 'could not get cert-authority from openspime configuration package.', 3)
                # set default path to keys if nothing has been forced in init params
                if rsa_pub_key_path == '':
                    rsa_pub_key_path = '%s/keys/public.pem' % osid_or_osid_path
                    self.log( 'rsa_pub_key_path set.', 3)
                if rsa_priv_key_path == '':
                    rsa_priv_key_path = '%s/keys/private.pem' % osid_or_osid_path
                    self.log( 'rsa_priv_key_path set.', 3)
                # set read values if nothing has been forced in init params
                if osid_pass == '' and c_osid_pass <> None:
                    osid_pass = c_osid_pass
                    self.log( 'osid_pass set.', 3)
                if server == '' and c_server <> None and c_server <> '':
                    server = c_server
                    self.log( 'c_server set.', 3)
                if port == 5222 and c_port <> None and c_port <> '':
                    port = c_port
                    self.log( 'c_port set.', 3)
                if rsa_priv_key_pass == '' and c_rsa_priv_key_pass <> None:
                    rsa_priv_key_pass = c_rsa_priv_key_pass
                    self.log( 'rsa_priv_key_pass set.', 3)
                if cert_authority == '' and c_cert_authority <> None:
                    cert_authority = c_cert_authority
                    self.log( 'cert_authority set.', 3)
            except:
                self.log('openspime configuration package is corrupted, aborting.', 0)
                exit(1004)
        
        # save
        self.osid = pyopenspime.xmpp.JID(osid_or_osid_path)
        self.osid_pass = osid_pass
        # get server if not explicitely stated
        if server == '':
            server = self.osid.getDomain()                
        self.Server = server
        self.Port = port
        
        # init
        self.__iq_callback_handlers = {}
        self.__iq_handler_functions = ()
        self.__stanza_waiting_pubkey = {}
        self.__outgoing_stanza_waiting_pubkey = {}
        self.__trying_reconnection = False
        
        # create EnDec object
        self._endec = EnDec()
        
        # load keys
        if rsa_pub_key_path <> '' and rsa_priv_key_path <> '':
            try:
                # convert to string -> M2Crypto needs str not unicode
                rsa_priv_key_pass = pyopenspime.util.to_utf8(rsa_priv_key_pass)
                self.__load_key_bio(rsa_pub_key_path, rsa_priv_key_path, rsa_priv_key_pass)
            except:
                self.log( u'error (%s) while loading RSA keys: %s.' % (unicode(sys.exc_info()[0].__name__), \
                                                                   unicode(sys.exc_info()[1])), 0)
                exit(1000)
        else:
            self._endec = None
        
        # check rsa_key_cache_path
        if rsa_key_cache_path <> '':
            # check that directory exists
            if os.path.isdir(rsa_key_cache_path) == False:
                # create cache directory if it does not exist
                self.log( 'cache directory does not exist, creating', 3)
                try:
                    os.mkdir(rsa_key_cache_path)
                    self.log( 'cache directory created.', 3)
                except:
                    self.rsa_key_cache_path = None
                    msg = u'specified key cache directory \'%s\' does not exist and could not be created.' % unicode(rsa_key_cache_path)
                    self.log(msg, 0)
                    exit(1001)
            else:
                # ensure slash or backslash is NOT included
                if rsa_key_cache_path[-1:] == '/' or rsa_key_cache_path[-1:] == '\\':
                    rsa_key_cache_path = rsa_key_cache_path[:-1]
                # save
                rsa_key_cache_path = rsa_key_cache_path
        # save
        self.rsa_key_cache_path = rsa_key_cache_path
        # save
        self.cert_authority = cert_authority
        # save
        if isinstance(try_reconnect, int) == False:
            self.log('reconnect must be expressed as integer.', 0)
            exit(1002)
        self.try_reconnect = try_reconnect
        
        # load accepted certified authorities        
        if accepted_cert_authorities_filepath <> '':
            if os.path.isfile(accepted_cert_authorities_filepath) == False:
                msg = u'specified accepted certified authorities file \'%s\' does not exist or cannot be accessed.' % unicode(accepted_cert_authorities_filepath)
                self.log(msg, 0)
                exit(1003)
            # read
            self.__accepted_cert_authorities = []
            f = open(accepted_cert_authorities_filepath, "r" )
            for line in f:
                line = line.strip().replace('\r','').replace('\n','')
                if len(line) > 0 and line[:1] <> '#':
                    self.__accepted_cert_authorities.append(line)
        else:
            self.__accepted_cert_authorities = None 
        
        # init component
        pyopenspime.xmpp.Client.__init__(self, self.osid.getDomain(), port, [])
        
        self.log(u'client succesfully initialized.', 2)
    
    def __setattr__(self, name, value):
        
        # set default
        self.__dict__[name] = value
    
    
    # ===\/=== private functions
    def __on_log(self, entry, verbosity):
        # private log fallback
        pass
    
    def __load_key_bio(self, rsa_pub_key_path, rsa_priv_key_path, rsa_priv_key_pass):
        """Loads the RSA key pair.
        @type  rsa_pub_key_path: unicode
        @param rsa_pub_key_path: The path to the RSA public key .pem file.
        @type  rsa_priv_key_path: unicode
        @param rsa_priv_key_path: The path to the RSA private key .pem file.
        @type  rsa_priv_key_pass: unicode
        @param rsa_priv_key_pass: The RSA private key .pem file password."""
        
        # create EnDec object 
        self.log(u'loading client RSA keys', 3)       
        try:
            self._endec = EnDec()
            self._endec.load_rsa_pub_key(rsa_pub_key_path)
            self._endec.load_rsa_priv_key(rsa_priv_key_path, rsa_priv_key_pass)
        except:
            self._endec = None
            raise
        self.log(u'client RSA keys successfully loaded.', 2)
    
    def __presence_handler(self, dispatcher, stanza):
        pass
    
    def __message_handler(self, dispatcher, stanza):
        # handles message stanzas
        
        msg_from = unicode(stanza.getFrom())
        msg_id = stanza.getID()
        self.log( u'received message from <%s>.' % (msg_from), 3)
        #############print "\r\nRECEIVED MESSAGE\r\n\r\n%s\r\n" % stanza
        # get openspime content
        self.log(u'check if incoming <message/> stanza is of the openspime protocol', 3)
        handler = self.__stanza_handler(stanza)
        if handler <> None:
            # ok stanza handled
            if handler[0] <> '':
                self.log( u'openspime extension found, calling callback handler', 3)
                # call handler
                self.on_openspime_extension_received(handler[0], handler[1], stanza)
                # return
                return True
        else:
            # stanza not handled
            pass
    
    def __iq_handler(self, dispatcher, stanza):
        
        # handles IQ stanzas - MUST return True if stanza is handled, False if not so that 'feature-not-implemented'
        # is sent back as response.
        
        iq_from = unicode(stanza.getFrom())
        iq_id = stanza.getID()
        self.log( u'received iq from <%s>.' % (iq_from), 3)
        ##############print "\r\nRECEIVED IQ\r\n\r\n%s\r\n" % stanza
        # check if <iq/> is of type 'error' or 'result'
        self.log(u'checking if received <iq/> is of type \'result\' or \'error\'', 3)
        if stanza.getType() == 'result' or stanza.getType() == 'error':
            # look if callbacks have been defined
            if self.__iq_callback_handlers.has_key(iq_id) == True:
                if stanza.getType() == 'result':
                    self.log(u'calling the callback_success function', 3)
                    # callback ok
                    self.__iq_callback_handlers[iq_id][0](iq_id, stanza)
                if stanza.getType() == 'error':
                    self.log(u'calling the callback_error function', 3)
                    # get error info
                    error = Error(stanza=stanza).get_error()
                    # callback ko
                    self.__iq_callback_handlers[iq_id][1](iq_id, error[0], error[1], stanza)
                # free key
                self.log(u'removing callback_handler key', 3)
                del self.__iq_callback_handlers[iq_id]
                # exit
                return True
        
        # check if received stanza is a pubkeys request
        if stanza.getType() == 'get':
            self.log(u'checking if received stanza is a pubkeys request', 3)
            if self.__iq_pubkey_request(stanza) == True:
                return True
        
        # get openspime content
        self.log(u'check if incoming <iq/> stanza is of the openspime protocol', 3)
        handler = self.__stanza_handler(stanza)
        if handler <> None:
            # ok stanza handled
            if handler[0] <> '':
                self.log( u'openspime \'%s\' extension found, calling callback' % handler[0], 3)
                # call handler
                self.on_openspime_extension_received(handler[0], handler[1], stanza)
                # return
                return True
        else:
            # stanza not handled, waiting to receive pubkey
            return True
    
    def __iq_callback_timeout(self):
        
        # loop all keys of dictionary
        for key in self.__iq_callback_handlers:
            if self.__iq_callback_handlers[key][3] < time.time():
                # timeout
                self.log(u'timeout waiting for reponse on <iq/> stanza with id \'%s\'.' % key, 3)
                self.log(u'calling timeout handler', 3)
                # callback
                self.__iq_callback_handlers[key][2](key)
                # free key
                self.log(u'removing callback_handler key', 3)
                del self.__iq_callback_handlers[key]
                break
    
    def __iq_pubkey_request(self, stanza):
        
        # check if stanza is a pubkey request
        iq_from = unicode(stanza.getFrom())
        iq_id = stanza.getID()
        found_request = False
        
        for child in stanza.getChildren():
            if child.getName() == 'pubkeys':
                # get request
                osid = child.getAttr('jid')
                if osid == self.osid:
                    if self._endec <> None:
                        # ok prepare response
                        self.log(u'request pubkey received, send public key', 3)
                        pubkey_iq = pyopenspime.xmpp.protocol.Iq(typ='result', to=iq_from)
                        pubkey_iq.setID(iq_id)
                        n_pubkey = pubkey_iq.addChild(u'pubkeys', namespace=u'urn:xmpp:tmp:pubkey', attrs={ u'jid': osid })
                        n_KeyInfo = n_pubkey.addChild(u'KeyInfo', namespace=u'http://www.w3.org/2000/09/xmldsig#')
                        n_RSAKeyValue = n_KeyInfo.addChild(u'RSAKeyValue')
                        n_Modulus = n_RSAKeyValue.addChild(u'Modulus')
                        n_Modulus.setData(binascii.b2a_base64(self._endec.rsa_pub_key.n).replace('\r','').replace('\n',''))
                        n_Exponent = n_RSAKeyValue.addChild(u'Exponent')
                        n_Exponent.setData(binascii.b2a_base64(self._endec.rsa_pub_key.e).replace('\r','').replace('\n',''))                   
                        self.log(u'sending pubkey response', 3)
                        self.send_stanza(pubkey_iq, iq_from)
                    else:
                        # ko prepare response no keys!
                        self.log(u'request pubkey received however no public RSA key has been specified, send error response.', 3)
                        # prepare response                
                        pubkey_iq = pyopenspime.xmpp.protocol.Iq(typ='error', to=iq_from)
                        pubkey_iq.setID(iq_id)
                        n_pubkey = pubkey_iq.addChild(u'pubkeys', namespace=u'urn:xmpp:tmp:pubkey', attrs={ u'jid': osid })
                        n_error = n_pubkey.addChild(u'error', attrs={ u'code': u'404', u'type': u'cancel' })
                        n_error_cond = n_error.addChild(u'no-available-public-key', \
                                                namespace=u'openspime:protocol:core:error')
                        self.log(u'sending error response', 3)
                        self.send_stanza(pubkey_iq, iq_from)  
                else:
                    self.log(u'request for another entity, send error', 3)
                    # prepare response                
                    pubkey_iq = pyopenspime.xmpp.protocol.Iq(typ='error', to=iq_from)
                    pubkey_iq.setID(iq_id)
                    n_pubkey = pubkey_iq.addChild(u'pubkeys', namespace=u'urn:xmpp:tmp:pubkey', attrs={ u'jid': osid })
                    n_error = n_pubkey.addChild(u'error', attrs={ u'code': u'404', u'type': u'cancel' })
                    n_error_cond = n_error.addChild(u'item-not-found', namespace=u'urn:ietf:params:xml:ns:xmpp-stanzas')
                    self.log(u'sending error response', 3)
                    self.send_stanza(pubkey_iq, iq_from)
                # remember
                found_request = True
        # return
        return found_request
    
    def __stanza_handler(self, stanza):
        
        """Handler to dispatch incoming openspime <message/> and <iq/> stanzas to proper extension.
        @type  stanza: pyopenspime.xmpp.protocol.Stanza
        @param stanza: The incoming stanza.
        @rtype:   tuple
        @return:  Tuple containing: (extname, extobj)."""
        
        # get stanza kind: <iq/>, <message/>
        stanza_kind = stanza.getName().strip().lower()
        
        # check that this is no error or result message
        self.log(u'checking that <message/> or <iq/> stanza is not of type \'result\' or \'error\'', 3)
        if stanza_kind == 'iq' and (stanza.getType() == 'result' or stanza.getType() == 'error'):
            return
        
        # check if signature has been provided, look for the <originator/> element
        self.log(u'get <originator/> node', 3)
        n_originator = pyopenspime.util.parse_all_children(stanza, 'originator')
        # loop children
        n_sign = None
        for child in n_originator.getChildren():
            if child.getName() == 'sign':
                # set sign node
                n_sign = child
                self.log(u'signature found.', 3)

                # check that client has a rsa_key_cache_path
                if self.rsa_key_cache_path == '':
                    self.log('a rsa key cache path needs to be set to send out encrypted messages, send error response.', 0)
                    # send error
                    self.log(u'sending error response.', 3)
                    iq_ko = Error(stanza, 'cancel', 'signature-not-enabled', 'openspime:protocol:core:error', \
                        'the incoming stanza has a signature, but the recipient entity is not enabled to verify signatures.')
                    self.send(iq_ko)
                    return
                
                # get originator
                if n_originator.getAttr('osid') <> None:
                    originator_osid = n_originator.getAttr('osid')
                else:
                    originator_osid = str(stanza.getFrom())
                # check if public key of originator is in cache
                self.log(u'get originator key from cache', 3)
                originator_osid_hex = binascii.b2a_hex(originator_osid)
                originator_key_fromcert_path = '%s/%s.fromcert' % (self.rsa_key_cache_path, originator_osid_hex)
                # check that filename 'fromcert' exists
                if os.path.isfile(originator_key_fromcert_path) == False:
                    # get cert authority
                    cert_osid = n_originator.getAttr('cert')
                    # request .fromcert key
                    self.__request_fromcert_key(stanza, originator_osid, cert_osid)                    
                    return
                break                    
        
        # check if decryption is needed, look for the <transport/> element
        self.log(u'get <transport/> node', 3)
        n_transport = pyopenspime.util.parse_all_children(stanza, 'transport')
        
        if n_transport <> None:
            # get encoding
            self.log(u'check encoding of incomed stanza', 3)
            attr = n_transport.getAttr('content-type')
            if attr == 'x-openspime/aes-base64':
                self.log(u'received message is encrypted.', 3)
                
                # check that client can decrytpt
                if self._endec == None:
                    self.log('incoming stanza is encrypted but no rsa key has been specified to decrypt it, send error response.', 0)
                    # send error
                    self.log(u'sending error response.', 3)
                    iq_ko = Error(stanza, 'cancel', 'decryption-not-enabled', 'openspime:protocol:core:error', \
                        'the incoming stanza was sent encrypted, but the recipient entity is not enabled to decrypt it.')
                    self.send(iq_ko)
                    return
                
                # content is encrypted -> get transport-key                
                self.log(u'get transport-key', 3)
                attr_transport_key = n_transport.getAttr('transport-key')
                # decrypt
                try:
                    self.log(u'trying to decrypt', 3)
                    decrypted_content = self._endec.private_decrypt(n_transport.getData(), attr_transport_key)
                except:
                    self.log(u'received message could not be decrypted, sending error.', 0)
                    # send error
                    self.log(u'sending error response.', 3)
                    iq_ko = Error(stanza, 'modify', 'decryption-error', 'openspime:protocol:core:error', \
                        'the incoming stanza was sent encrypted, though there were errors decrypting it (wrong public RSA key of recipient?).')
                    self.send(iq_ko)
                    return
                self.log(u'message has succesfully been decrypted.', 3)
                # parse
                try:
                    # empty node
                    self.log(u'substituting content of <transport/> node', 3)
                    n_transport = pyopenspime.util.clean_node(n_transport)
                    # create transport child
                    n_transport_child = pyopenspime.xmpp.simplexml.Node(node=decrypted_content)
                    # add decrypted content to the <transport/> node
                    n_transport.addChild(node=n_transport_child)
                    # remove "content-type" and "transport-key" attributes of <transport/> node
                    n_transport.delAttr('content-type')
                    n_transport.delAttr('transport-key')
                except:
                    self.log(u'malformed <transport/> node in received message, sending error.', 0)
                    # send error
                    self.log(u'sending error response.', 3)
                    iq_ko = Error(stanza, 'modify', 'xml-malformed-transport-node', 'openspime:protocol:core:error', \
                            'the incoming stanza has been decrypted, but the <transport/> node contains non valid xml.')
                    self.send(iq_ko)
                    return
        
        # check if signature has been provided, verify signature
        if n_sign <> None:                    
            # create endec object
            endec = EnDec()
            try:
                self.log(u'loading originator public RSA key', 3)
                endec.load_rsa_pub_key(originator_key_fromcert_path)
            except:           
                # check time of fromcert public RSA key
                sign_info = os.stat(originator_key_fromcert_path)
                if time.time() - sign_info.st_mtime > 200:
                    self.log(u'error loading originator public RSA key, requesting newer key', 3)
                    # get cert authority
                    cert_osid = n_originator.getAttr('cert')
                    # request .fromcert key
                    self.__request_fromcert_key(stanza, originator_osid, cert_osid)
                else:
                    # key corrupted
                    self.log(u'originator public certified RSA key corruped, signature cold not be verified, sending error.', 0)
                    # send error
                    self.log(u'sending error response.', 3)
                    iq_ko = Error(stanza, 'cancel', 'signature-error-public-key-corrupted', 'openspime:protocol:core:error', \
                        'the incoming stanza has a signature which could not be validated because the public RSA key of the originator received from the cert authority is corrupted.')
                    self.send(iq_ko)
                return
            # get signature                
            self.log(u'get signature', 3)
            signature = child.getData()      
            self.log(u'get content of <transport/> node', 3)
            try:
                content = n_transport.getChildren()[0]
            except:
                # send error
                self.log(u'sending error response.', 3)
                iq_ko = Error(stanza, 'modify', 'xml-malformed-transport-node', 'openspime:protocol:core:error', \
                        'the incoming stanza has been decrypted, but the <transport/> node contains non valid xml.')
                self.send(iq_ko)
                return
            # check
            self.log(u'verifying signature', 3)
            if endec.public_check_sign(content, signature) == True:
                self.log(u'signature was succesfully verified.', 3)
            else:              
                # check time of fromcert public RSA key
                sign_info = os.stat(originator_key_fromcert_path)
                if time.time() - sign_info.st_mtime > 200:
                    self.log(u'signature cold not yet be verified, requesting newer key', 3)
                    # get cert authority
                    cert_osid = n_originator.getAttr('cert')
                    # request .fromcert key
                    self.__request_fromcert_key(stanza, originator_osid, cert_osid)
                else:
                    self.log(u'signature cold not be verified, even with a recent key, sending error.', 0)                    
                    # send error
                    self.log(u'sending error response.', 3)
                    iq_ko = Error(stanza, 'modify', 'invalid-signature', 'openspime:protocol:core:error', \
                            'the incoming stanza has a signature which could not be validated. ')
                    self.send(iq_ko)
                return
        # import extensions
        for ext in PYOPENSPIME_EXTENSIONS_LOADED:
            # example: import pyopenspime.extension.datareporting
            self.log(u'trying \'%s\' extension for validity' % ext, 3)
            exec( 'import pyopenspime.extension.%s' % ext )
            # call extension validate function
            exec( 'result = pyopenspime.extension.%s.validate(stanza)' % ext )
            if result == True:
                # ok we have a match, call core main function                
                self.log(u'extension \'%s\' matches, calling main function' % ext, 3)
                exec( 'extobj = pyopenspime.extension.%s.main(stanza)' % ext )
                self.log(u'received \'%s\' extension object.' % ext, 3)
                return (ext, extobj)
            else:           
                self.log(u'extension \'%s\' does not match.' % ext, 3)
    
    def __request_fromcert_key(self, stanza, originator_osid, cert_osid):
        
        # check if in accepted_cert_authorities
        if not cert_osid in self.__accepted_cert_authorities:
            self.log(u'cert authority \'%s\' not in cert authorities list, sending error.', 0)
            # send error
            self.log(u'sending error response.', 3)
            iq_ko = Error(stanza, 'modify', 'signature-error-invalid-cert-auth', 'openspime:protocol:core:error', \
                'the incoming stanza has a signature certified by a certification authority not accepted by the recipient entity.')
            self.send(iq_ko)
            return
        # key is not in cache, download from cert authority
        pubkey_iq = pyopenspime.xmpp.protocol.Iq(typ='get', to=cert_osid)
        pubkey_iq.addChild(u'pubkeys', namespace=u'urn:xmpp:tmp:pubkey', \
                attrs={ 'jid': originator_osid })
        self.log(u'sending pubkey request to cert authority <%s>' % cert_osid, 3)
        ID = self.send_stanza_with_handlers(pubkey_iq, \
                callback_success=self.__pubkey_fromcert_verify_signature_ok, \
                callback_error=self.__pubkey_fromcert_verify_signature_ko, \
                callback_timeout=self.__pubkey_fromcert_verify_signature_timeout, timeout=30)
        # save stanza in memory
        self.__stanza_waiting_pubkey[ID] = stanza
    
    def __treat_pubkey_response_and_save_key_bio(self, stanza, fromcert=False):
        
        """Treats an incoming pubkey stanza and saves the public key to a .pem file
        @type  stanza: pyopenspime.xmpp.protocol.Iq
        @param stanza: The response to a pubkey request.
        @type  fromcert: boolean
        @param fromcert: Set to I{True} if response comes from a cert authority. Defaults to I{False}.
        @rtype:   boolean
        @return:  True if succesful, False if errors encountered."""
        
        found = False
        for child in stanza.getChildren():
            if child.getName() == 'pubkeys':
                # ok at least one pubjkey found
                found = True
                # get osid of key owner
                osid_key_owner = child.getAttr('jid')
                # get values
                n_RSAKeyValue = pyopenspime.util.parse_all_children(child, 'RSAKeyValue', True)
                n_Modulus = pyopenspime.util.parse_all_children(n_RSAKeyValue, 'Modulus', True)
                n_Exponent = pyopenspime.util.parse_all_children(n_RSAKeyValue, 'Exponent', True)
                # create key
                try:
                    new_pub_key = M2Crypto.RSA.new_pub_key((binascii.a2b_base64(n_Exponent.getData()), \
                                                            binascii.a2b_base64(n_Modulus.getData())))
                    # osid name
                    osid_key_owner_hex = binascii.b2a_hex(osid_key_owner)
                    osid_key_owner_key_path = '%s/%s' % (self.rsa_key_cache_path, osid_key_owner_hex)
                    if fromcert == True:
                        osid_key_owner_key_path = '%s.fromcert' % osid_key_owner_key_path                    
                    # save 'fromcert' key
                    new_pub_key.save_pub_key(osid_key_owner_key_path)
                except:
                    return False
        return found
    
    def __pubkey_fromcert_verify_signature_ok(self, stanza_id, stanza):
        
        self.log( "received response from cert authority on pubkey request with id \'%s\', can now verify signature." % stanza_id, 3)
        
        # save received key(s) from cert
        if self.__treat_pubkey_response_and_save_key_bio(stanza, True) == False:
            # XXXXXXXXXX
            raise
        # treat waiting stanza
        self.__iq_handler(self.Dispatcher, self.__stanza_waiting_pubkey[stanza_id])
        # clear stanza handle
        self.log(u'removing stanza_waiting_pubkey key', 3)
        del self.__stanza_waiting_pubkey[stanza_id]
    
    def __pubkey_fromcert_verify_signature_ko(self, stanza_id, error_cond, error_description, stanza):
        
        self.log( "received error (%s) from cert authority on pubkey request with id \'%s\', cannot verify signature." % (error_cond,stanza_id), 3)
        # clear stanza handle
        self.log(u'removing stanza_waiting_pubkey key', 3)
    
    def __pubkey_fromcert_verify_signature_timeout(self):
        
        self.log( "timeout waiting for response from cert authority on pubkey request with id \'%s\', cannot verify signature." % stanza_id, 3)
        # clear stanza handle
        self.log(u'removing stanza_waiting_pubkey key', 3)
    
    def __encrypt_and_sign(self, stanza, encrypt=False, sign=False):
        
        """Function that manages encryption and signature of the OpenSpime Core Reference Schema.

        Reference is OpenSpime protocol Core Reference Schema v0.9.

        @type  encrypt: boolean
        @param encrypt: If encryption is requested, set to True. Defaults to I{False}.
        @type  sign: boolean
        @param sign: If signature is requested, set to True. Defaults to I{False}.
            
        @rtype:   pyopenspime.xmpp.simplexml.Node
        @return:  The <openspime/> encrypted and signed node."""
        
        # get the <openspime/> node
        n_openspime = pyopenspime.util.parse_all_children(stanza, 'openspime')
        
        # check if something needs to be done
        if n_openspime <> None and (encrypt == True or sign == True):
            
            # get to
            to_osid = str(stanza.getTo())
            
            if encrypt == True:
                
                # if encryption is requested, check that we have the recipient public RSA key
                self.log(u'get recipient key from cache', 3)
                to_osid_hex = binascii.b2a_hex(to_osid)
                to_osid_key_path = '%s/%s' % (self.rsa_key_cache_path, to_osid_hex)
                # check that filename 'fromcert' exists
                if os.path.isfile('%s.fromcert' % to_osid_key_path) == True:
                    self.log(u'recipient cert key found in cache', 3)
                    to_osid_key_path = '%s.fromcert' % to_osid_key_path
                elif os.path.isfile(to_osid_key_path) == True:
                    self.log(u'recipient non-cert key found in cache', 3)
                else:
                    # key is not in cache, download from recipient entity
                    self.log(u'recipient key not found in cache, requesting it directly', 3)
                    pubkey_iq = pyopenspime.xmpp.protocol.Iq(typ='get', to=to_osid)
                    pubkey_iq.addChild(u'pubkeys', namespace=u'urn:xmpp:tmp:pubkey', \
                            attrs={ 'jid': to_osid })
                    self.log(u'sending pubkey request directly to entity <%s>' % to_osid, 3)
                    ID = self.send_stanza_with_handlers(pubkey_iq, \
                                       callback_success=self.__pubkey_from_entity_send_ok, \
                                       callback_error=self.__pubkey_from_entity_send_ko, \
                                       callback_timeout=self.__pubkey_from_entity_send_timeout, timeout=20)
                    
                    # save stanza in memory
                    self.__outgoing_stanza_waiting_pubkey[ID] = (stanza, encrypt, sign)
                    # exit
                    return None
            
            # get from
            originator_osid = str(stanza.getFrom())
            # get <originator/> node
            n_originator = pyopenspime.util.parse_all_children(n_openspime, 'originator')
            # get <transport/> node
            n_transport = pyopenspime.util.parse_all_children(n_openspime, 'transport')
            # get first child of transport
            children = n_transport.getChildren()
            if children <> None:
                transport_child_content = str(children[0])
            else:
                transport_child_content = ''
            
            # sign
            if sign == True:
                
                # get <originator/> node
                n_originator = pyopenspime.util.parse_all_children(n_openspime, 'originator')
                if n_originator <> None:
                    if n_originator.getAttr('osid') <> None:
                        # get from
                        originator_osid = n_originator.getAttr('osid')
                else:
                    # create node
                    n_originator = n_transport.addChild(name=u'originator')
                # add cert authority
                if self.cert_authority <> '':
                    n_originator.setAttr('cert', self.cert_authority)
                else:
                    raise Exception, 'no cert authority has been set for client, cannot sign openspime message.'                # add signature    
                self.log(u'computing signature', 3)
                signature = self._endec.private_sign(transport_child_content)
                self.log(u'adding signature node', 3)
                n_sign = n_originator.addChild(name=u'sign')
                n_sign.addData(signature)
            
            # encrypt
            if encrypt == True:
                self.log(u'adding <tranport/> node \'content-type\' encrypted attribute', 3)
                n_transport.setAttr('content-type', 'x-openspime/aes-base64')                
                # encrypt content
                self.log(u'loading public RSA key of recipient', 3)
                endec = EnDec()
                endec.load_rsa_pub_key(to_osid_key_path)
                self.log(u'encrypting', 3)
                encrypted = endec.public_encrypt(transport_child_content)
                n_transport = pyopenspime.util.clean_node(n_transport)
                n_transport.setData(encrypted[0])
                n_transport.setAttr('transport-key', encrypted[1])
        
        # return
        return stanza
    
    def __pubkey_from_entity_send_ok(self, stanza_id, stanza):

        self.log( "received response from entity on pubkey request with id \'%s\', can now send message." % stanza_id, 3)
        
        # save received key(s) from cert
        if self.__treat_pubkey_response_and_save_key_bio(stanza, False) == False:
            # XXXXXXXXXX
            raise
        # treat waiting stanza
        self.send_stanza(self.__outgoing_stanza_waiting_pubkey[stanza_id][0], \
                         self.__outgoing_stanza_waiting_pubkey[stanza_id][0].getTo(), \
                         self.__outgoing_stanza_waiting_pubkey[stanza_id][1], \
                         self.__outgoing_stanza_waiting_pubkey[stanza_id][2])
        # clear stanza handle
        self.log(u'removing outgoing_stanza_waiting_pubkey key', 3)
        del self.__outgoing_stanza_waiting_pubkey[stanza_id]
    
    def __pubkey_from_entity_send_ko(self, stanza_id, error_cond, error_description, stanza):

        self.log( "received error (%s) from entity on pubkey request with id \'%s\', cannot send message." % (error_cond,stanza_id), 3)
        # clear stanza handle
        self.log(u'removing outgoing_stanza_waiting_pubkey key', 3)
        del self.__outgoing_stanza_waiting_pubkey[stanza_id]
    
    def __pubkey_from_entity_send_timeout(self, stanza_id):

        self.log( "timeout waiting for response from entity on pubkey request with id \'%s\', cannot send message." % stanza_id, 3)
        # clear stanza handle
        self.log(u'removing outgoing_stanza_waiting_pubkey key', 3)
        del self.__outgoing_stanza_waiting_pubkey[stanza_id]
    
    def __reconnect(self):
        
        # reconnect client
        try:
            self.__handlerssave = self.Dispatcher.dumpHandlers()
            self.log('handlers dumped.', 3)
            if self.__dict__.has_key('ComponentBind'): self.ComponentBind.PlugOut()
            if self.__dict__.has_key('Bind'): self.Bind.PlugOut()
            self._route=0
            if self.__dict__.has_key('NonSASL'): self.NonSASL.PlugOut()
            if self.__dict__.has_key('SASL'): self.SASL.PlugOut()
            if self.__dict__.has_key('TLS'): self.TLS.PlugOut()
            self.Dispatcher.PlugOut()
            self.log('dispatcher plugged out.', 3)
            if self.__dict__.has_key('HTTPPROXYsocket'): self.HTTPPROXYsocket.PlugOut()
            if self.__dict__.has_key('TCPsocket'): self.TCPsocket.PlugOut()
        except:
            pass
        try:
            self.connect()
            try:
                self.Dispatcher.restoreHandlers(self.__handlerssave)
            except:
                pass
            self.__handlerssave = None
            self.log('reconnected.', 3)
            self.__trying_reconnection = False
        except:
            self.log('error while reconnecting, retrying in %s seconds.' % self.try_reconnect, 1)
            time.sleep(self.try_reconnect)
            self.__reconnect()
    
    
    ###### Events functions
    def DisconnectHandler(self):

        """Handler to manage automatic reconnection."""

        if self.__trying_reconnection == False:
            self.__trying_reconnection = True
            self.log('client is disconnected, trying automatic reconnection every %s seconds.' % self.try_reconnect, 1)
            self.__reconnect()
    
    def on_openspime_extension_received(self, ext_name, ext_object, stanza):

        """Event raised when an OpenSpime stanza is received. This one does nothing, should be overriden in
        derived classes.

        @type  ext_name: unicode
        @param ext_name: The extension name.
        @type  ext_object: unicode
        @param ext_object: The extension object (varies according to extensions).
        @type  stanza: pyopenspime.xmpp.protocol.Protocol
        @param stanza: The stanza, to be used for advanced treatment."""
        
        pass
    
    
    ###### Support functions
    def connect(self):

        """Connects the Client to the server and initializes handlers."""

        # connect
        self.log(u'connecting to <%s>' % unicode(self.Server), 2)
        if pyopenspime.xmpp.Client.connect(self) == "":
            msg = u'could not connect to server <%s>, aborting.' % unicode(self.Server)
            self.log(msg, 0)
            raise Exception, msg
        self.log(u'connected.', 3)

        # authenticate
        self.log(u'authenticating client on server', 2)
        if pyopenspime.xmpp.Client.auth(self, self.osid.getNode(), self.osid_pass, self.osid.getResource()) == None:
            msg = u'could not authenticate, aborting. check osid and password.'
            self.log(msg, 0)
            raise Exception, msg
        self.log(u'authenticated.', 3)

        # notify presence
        self.log(u'notifying presence', 3)
        self.sendInitPresence(0)

        # register handlers
        self.log(u'registering presence handler', 3)
        self.RegisterHandler('presence', self.__presence_handler)
        self.log(u'registering message handler', 3)
        self.RegisterHandler('message', self.__message_handler)
        self.log(u'registering iq handler', 3)
        self.RegisterHandler('iq', self.__iq_handler)

        self.log(u'client ready.', 2)
    
    def loop(self):
        """Main listening loop for the client. Handles events."""

        # main client loop
        result = self.Process(1)
        if result == True:
            self.log(u'incoming malformed xml, ignored.', 1) 
        # handle iq callback timeout
        self.__iq_callback_timeout()
    
    def set_iq_handlers(self, callback_success=None, callback_error=None, callback_timeout=None, timeout=60):
        """Sets the handlers for <iq/> stanzas.

        @type  callback_success: function
        @param callback_success: Callback function called when a 'result' response is received.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.
        @type  callback_error: function
        @param callback_error: Callback function called when a 'error' response is received.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.
        @type  callback_timeout: function
        @param callback_timeout: Callback function called when no response is received after the timeout period.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.
        @type  timeout: int
        @param timeout: If a callback_timeout function has been specified, this parameter specifies the timeout in seconds
            after which the callback_timeout function is called if no response is received. This parameter
            also specifies the time life of the callback_success and callback_error functions, after which their 
            handler will be removed.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza."""
        
        self.log(u'setting iq handlers', 3)
        if isinstance(timeout, int) == False:
            raise Exception, 'timeout must be expressed in integer seconds.'        
        self.__iq_handler_functions = (callback_success, callback_error, callback_timeout, timeout)
    
    def send_stanza(self, stanza, to_osid, encrypt=False, sign=False):
        """Sends out a stanza.
        @type  stanza: pyopenspime.xmpp.protocol.Protocol
        @param stanza: The stanza to be sent.
        @type  to_osid: unicode
        @param to_osid: The recipient of the message. 
        @type  encrypt: boolean
        @param encrypt: If encryption is requested, set to True. Defaults to I{False}.
        @type  sign: boolean
        @param sign: If signature is requested, set to True. Defaults to I{False}."""
        
        self.log(u'setting \'from\' and \'to\' attribute of stanza', 3)
        stanza.setFrom(self.osid)
        stanza.setTo(to_osid)
        # encrypt and sign if necessary
        if encrypt == True or sign == True:
         
            stanza = self.__encrypt_and_sign(stanza, encrypt=encrypt, sign=sign)
            if stanza == None:
                # we need to wait for public rsa key of recipient, exit sending for now
                return
        # add iq handlers
        if stanza.getName().strip().lower() == 'iq':
            if self.__iq_handler_functions <> None and (stanza.getType() == 'set' or stanza.getType() == 'get'):                # add key
                self.log(u'creating callback handler', 3)
                self.__iq_callback_handlers[stanza.getID()] = (self.__iq_handler_functions[0], self.__iq_handler_functions[1], \
                                                   self.__iq_handler_functions[2], \
                                                   time.time() + self.__iq_handler_functions[3])        
        # send
        self.log(u'sending stanza', 3)
        self.Dispatcher.send(stanza)  
    
    def send_stanza_with_handlers(self, stanza, callback_success=None, callback_error=None, callback_timeout=None, timeout=60):
        
        """Sends out a stanza with function handlers specified directly. This is NOT to be used for OpenSpime messages.

        @type  stanza: pyopenspime.xmpp.protocol.Protocol
        @param stanza: The stanza to be sent.
        @type  callback_success: function
        @param callback_success: Callback function called when a 'result' response is received.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.
        @type  callback_error: function
        @param callback_error: Callback function called when a 'error' response is received.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.
        @type  callback_timeout: function
        @param callback_timeout: Callback function called when no response is received after the timeout period.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.
        @type  timeout: int
        @param timeout: If a callback_timeout function has been specified, this parameter specifies the timeout in seconds
            after which the callback_timeout function is called if no response is received. This parameter
            also specifies the time life of the callback_success and callback_error functions, after which their 
            handler will be removed.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.

        @rtype:   unicode
        @return:  ID of sent stanza."""
        
        self.log(u'setting \'from\' attribute of stanza', 3)
        stanza.setFrom(self.osid)
        if callback_success <> None or callback_error <> None or callback_timeout <> None:
            if stanza.getName().strip().lower() == 'iq':
                self.log(u'serializing the stanza id', 3)
                if stanza.getID() == None:
                    # serialize id
                    ID = self.serialize()
                    stanza.setID(ID)
                # add key
                self.log(u'creating callback handler', 3)
                self.__iq_callback_handlers[ID] = (callback_success, callback_error, callback_timeout, time.time()+timeout)

        # send and return ID
        self.log(u'sending stanza', 3)
        return unicode(self.Dispatcher.send(stanza))       
    
    def serialize(self):

        return pyopenspime.util.generate_rnd_str(16)
    
    def disconnect(self):
        """Disconnects from server and handles all incoming stanzas before closure."""
         
        # never called. self.Dispatcher.disconnect() is directly called via the plugin architecture.
        # here for manual completeness only.
        
        pass
    


class EnDec():
    """Encrypter-Decrypted object.
    This object is used to encrypt, descrypt and sign OpenSpime stanzas. It includes RSA and AES support as
    defined in the OpenSpime Core Protocol v0.9."""

    def __init__(self):
        
        """Initialize an EnDec object."""
     
        self.rsa_pub_key_path = ''
        self.rsa_pub_key = None 
        self.rsa_priv_key_path = ''
        self.rsa_priv_key_pass = ''
        self.rsa_priv_key = None
    
    def load_rsa_pub_key(self, rsa_pub_key_path):
        
        """Load public RSA key from .pem file.

        @type  rsa_pub_key_path: unicode
        @param rsa_pub_key_path: The path to the RSA public key .pem file."""
        
        self.rsa_pub_key_path = rsa_pub_key_path
        self.rsa_pub_key = M2Crypto.RSA.load_pub_key(rsa_pub_key_path)
    
    def load_rsa_priv_key(self, rsa_priv_key_path, rsa_priv_key_pass):  
        
        """Load private RSA key from .pem file.

        @type  rsa_priv_key_path: unicode
        @param rsa_priv_key_path: The path to the RSA private key .pem file.
        @type  rsa_priv_key_pass: unicode
        @param rsa_priv_key_pass: The RSA private key .pem file password."""      
        
        self.rsa_priv_key_path = rsa_priv_key_path
        self.rsa_priv_key_pass = rsa_priv_key_pass
        self.rsa_priv_key = M2Crypto.RSA.load_key(rsa_priv_key_path, callback=self.__rsa_callback_get_passphrase)        
    
    def __rsa_callback_get_passphrase(self, v):
        
        return self.rsa_priv_key_pass
    
    def __aes_encrypt_base64(self, plaintext, aes_key, aes_vint):

        # AES encryption
        mem = M2Crypto.BIO.MemoryBuffer()
        cf = M2Crypto.BIO.CipherStream(mem)
        cf.set_cipher('aes_256_cbc', aes_key, aes_vint, 1)
        cf.write(plaintext)
        cf.flush()
        cf.write_close()
        cf.close()
        return binascii.b2a_base64(mem.read())
    
    def __aes_decrypt_base64(self, encrypted, aes_key, aes_vint):

        # AES decryption
        mem = M2Crypto.BIO.MemoryBuffer(binascii.a2b_base64(encrypted))
        cf = M2Crypto.BIO.CipherStream(mem)
        cf.set_cipher('aes_256_cbc', aes_key, aes_vint, 0)
        cf.write_close()
        decrypted = cf.read()
        cf.close()
        return decrypted
    
    def __rsa_public_encrypt_base64(self, plaintext):

        # RSA public encryption

        # get pub_key size
        s = int(( self.rsa_pub_key.__len__() ) / 8) - 11    # take away 11 bytes due to pkcs1_padding
        encrypted = []
        # chunk encrypt
        for i in range(0, len(plaintext), s):
            encrypted.append(self.rsa_pub_key.public_encrypt(plaintext[i:i+s], M2Crypto.RSA.pkcs1_padding))
        # return base64 encoded
        return binascii.b2a_base64(''.join(encrypted))
    
    def __rsa_private_decrypt_base64(self, encrypted):

        # RSA private decryption

        encrypted = binascii.a2b_base64(encrypted)
        # get pub_key size
        s = int(self.rsa_priv_key.__len__() / 8)
        decrypted = []
        # chunk decrypt
        for i in range(0, len(encrypted), s):
            decrypted.append(self.rsa_priv_key.private_decrypt(encrypted[i:i+s], M2Crypto.RSA.pkcs1_padding))
        # return
        return ''.join(decrypted)
    
    def __rsa_private_encrypt_base64(self, plaintext):

        # RSA private encryption

        # get pub_key size
        s = int(( self.rsa_pub_key.__len__() ) / 8) - 11    # take away 11 bytes due to pkcs1_padding
        encrypted = []
        # chunk encrypt
        for i in range(0, len(plaintext), s):
            encrypted.append(self.rsa_priv_key.private_encrypt(plaintext[i:i+s], M2Crypto.RSA.pkcs1_padding))
        # return base64 encoded
        return binascii.b2a_base64(''.join(encrypted))
    
    def __rsa_public_decrypt_base64(self, encrypted):

        # RSA public decryption

        encrypted = binascii.a2b_base64(encrypted)
        # get pub_key size
        s = int(self.rsa_pub_key.__len__() / 8)
        decrypted = []
        # chunk decrypt
        for i in range(0, len(encrypted), s):
            decrypted.append(self.rsa_pub_key.public_decrypt(encrypted[i:i+s], M2Crypto.RSA.pkcs1_padding))
        # return
        return ''.join(decrypted)
    
    def public_encrypt(self, transport):
        
        """Encrypts the content of the transport node with public key of recipient.

        @type  transport: unicode
        @param transport: The <transport/> node content to be encrypted.

        @rtype:   tuple
        @return:  Tuple containing: (base64 encrypted transport, base64 encrypted transport-key)."""
        
        # generate a random 32 bytes AES key
        aes_key = M2Crypto.m2.rand_bytes(32)

        # generate a random 16 bytes init vector data
        aes_vint = M2Crypto.m2.rand_bytes(16)

        # encrypt in AES and encode to base64
        encrypted = self.__aes_encrypt_base64(transport, aes_key, aes_vint).replace('\r', '').replace('\n', '')
        
        # generate the content of the 'transport-key' attribute
        transport_key = u"<transportkey xmlns='openspime:protocol:core:transportkey' version='0.9'> \
            <key>%s</key><vint>%s</vint> \
            </transportkey>" % ( binascii.b2a_base64(aes_key).replace('\r', '').replace('\n', ''), \
                                 binascii.b2a_base64(aes_vint).replace('\r', '').replace('\n', '') )

        transport_key = pyopenspime.util.to_utf8(transport_key)

        # encrypt the transport key with the public RSA key of recipient
        transport_key_enc = self.__rsa_public_encrypt_base64(transport_key).replace('\r', '').replace('\n', '')

        # return tuple
        return [encrypted, transport_key_enc]
    
    def private_decrypt(self, encrypted, transport_key_enc):
        
        """Decrypts a string encoded with public key of recipient.

        @type  encrypted: str
        @param encrypted: The base64 encrypted content of the <transport/> node.
        @type  transport_key_enc: str
        @param transport_key_enc: The base64 encrypted transport-key.

        @rtype:   str
        @return:  The decrypted <transport/> node content."""
        
        # decrypt the transport key with the private RSA key of recipient
        transport_key = self.__rsa_private_decrypt_base64(transport_key_enc)
        
        # read transportkey: create parser
        n_transport_key = pyopenspime.xmpp.simplexml.Node(node=transport_key)
        # parse
        for child in n_transport_key.getChildren():
            if child.getName().strip().lower() == 'key':
                aes_key = binascii.a2b_base64(child.getData())
            if child.getName().strip().lower() == 'vint':
                aes_vint = binascii.a2b_base64(child.getData())

        # decrypt transport content
        return self.__aes_decrypt_base64(encrypted, aes_key, aes_vint)
    
    def private_sign(self, content):
        
        """Returns the value of the signature of a the <transport/> node. Reference is OpenSpime protocol v0.9.

        @type  content: str
        @param content: The string content of the <transport/> node.

        @rtype:   str
        @return:  The base64 encoded signature of the <transport/> node."""
        
        # convert to canonical XML
        content_canonical = pyopenspime.util.convert_to_canonical_xml(content)

        # compute sha
        s = sha.sha(content_canonical).digest()

        # encrypt the sha using the private RSA key
        return self.__rsa_private_encrypt_base64(s).replace('\r', '').replace('\n', '')
    
    def public_check_sign(self, content, signature):
        """Returns the value of the signature of a the <transport/> node. Reference is OpenSpime protocol v0.9.

        @type  content: str
        @param content: The string content of the <transport/> node.
        @type  signature: str
        @param signature: The signature.

        @rtype:   boolean
        @return:  True if signature is valid, False if it is not."""
        
        # convert to canonical XML
        content_canonical = pyopenspime.util.convert_to_canonical_xml(content)

        # compute sha
        s = sha.sha(content_canonical).digest()

        # get the sha in the signature
        try:
            sha_in_signature = self.__rsa_public_decrypt_base64(signature)
        except:
            return False

        return s == sha_in_signature        
    

class Error(pyopenspime.xmpp.protocol.Iq):
    """PyOpenSpime Error stanza."""
    
    def __init__(self, stanza, error_type='modify', error_cond=None, error_namespace=None, error_description=None):  
        """Initialize an OpenSpime error stanza.

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
        @param error_description: The error description."""
        
        # init component
        pyopenspime.xmpp.protocol.Iq.__init__(self, node=stanza)

        if error_cond <> None:

            # we are building a node

            # invert recipient and sender
            frm = self.getFrom()
            to = self.getTo()
            self.setTo(frm)
            self.setFrom(to)

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

        """Retrieves error condition and description from an error stanza.
        Reference is OpenSpime protocol Core Reference Schema v0.9.
        @rtype:   tuple of unicode
        @return:  (error_cond, error_description)"""
        
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
        
        return (error_cond, error_description)
    

def wrap(transport_child_node, originator_osid=None, transport_to_osid=None):
    """Function that manages the OpenSpime Core Reference Schema. Used by extensions to build a complete <openspime/> node,
    before encryption and sign.
    
    Reference is OpenSpime protocol Core Reference Schema v0.9.
    
    @type  transport_child_node: pyopenspime.xmpp.simplexml.Node
    @type  originator_osid: unicode
    @param originator_osid: Sets 'osid' attribute of the <originator/> element. Defaults to I{None}.
    @type  transport_to_osid: unicode
    @param transport_to_osid: Sets 'to' attribute of the <transport/> element. Defaults to I{None}.
    @rtype:   pyopenspime.xmpp.simplexml.Node
    @return:  The <openspime/> node."""
    
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
    










    


    

