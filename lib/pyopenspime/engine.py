#
# PyOpenSpime - Protocol Engine Module
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

"""Protocol Engine Module."""

# imports
import sys, os, binascii, time
import pyopenspime.xmpp, pyopenspime.util
from pyopenspime.protocol.extension.conf import *
from pyopenspime.protocol.core import Error
from pyopenspime.ssl import EnDec


# engine errors definition
class EngineError(Exception):
    def __init__(self, errordesc):
        self.errordesc = errordesc
    def __str__(self):
        return self.errordesc
class RecipientPublicKeyNotInCache(EngineError): pass
class DecryptionError(EngineError): pass
class MissingPrivateKey(EngineError): pass
class MalformedXML(EngineError): pass
class KeyCachePathNotSet(EngineError): pass
class SigneeCertifiedPublicKeyFromUnauthCert(EngineError): pass
class SigneeCertifiedPublicKeyNotInCache(EngineError): pass
class SigneeCertifiedPublicKeyCorruptedRetry(EngineError): pass
class SigneeCertifiedPublicKeyCorrupted(EngineError): pass


class StanzaInterpreter():
    """
    Class that handles all outgoing requests and incoming responses. This class also handles key cache management.
    """
   
    def __init__(self, osid_or_osid_path, rsa_pub_key_path='', rsa_priv_key_path='', rsa_priv_key_pass='', rsa_key_cache_path='cache', cert_authority='', \
                accepted_cert_authorities_filepath='certification-authorities.conf', log_callback_function=None):
        """
        Initializes a StanzaInterpreter.
        
        @type  osid_or_osid_path: str
        @param osid_or_osid_path: The full OSID of the client. If an OpenSpime configuration package is found, this is
            the only parameter that is needed to initialize the Client.
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
        @type  log_callback_function: function
        @param log_callback_function: Callback function for logger. Function should accept two parameters: unicode
            (the log description) and integer (the verbosity level - 0 for error, 1 for warning, 2 for info,
            3 for debug).
        """
        
        # set log callback function
        if log_callback_function != None:
            self.log = log_callback_function
                
        # try to get openspime package
        ospackage_info = pyopenspime.util.OsPackage(osid_or_osid_path, self.log).read()
        if ospackage_info <> None:
            # get values from package if nothing has been forced in init params
            if cert_authority == '': cert_authority = ospackage_info['cert_authority']
            if rsa_pub_key_path == '': rsa_pub_key_path = ospackage_info['rsa_pub_key_path']
            if rsa_priv_key_path == '': rsa_priv_key_path = ospackage_info['rsa_priv_key_path']
            if rsa_priv_key_pass == '': rsa_priv_key_pass = ospackage_info['rsa_priv_key_pass']
        
        # save
        self.osid = pyopenspime.xmpp.JID(osid_or_osid_path)
        self.cert_authority = cert_authority
        self.accepted_cert_authorities_filepath = accepted_cert_authorities_filepath

        # check rsa_key_cache_path
        if rsa_key_cache_path <> '':
            # check that directory exists
            if os.path.isdir(rsa_key_cache_path) == False:
                # create cache directory if it does not exist
                self.log(10, 'rsa cache directory does not exist, creating')
                try:
                    os.mkdir(rsa_key_cache_path)
                    self.log(10, 'rsa cache directory created.')
                except:
                    self.rsa_key_cache_path = None
                    msg = u'specified key cache directory \'%s\' does not exist and could not be created.' % unicode(rsa_key_cache_path)
                    self.log(40, msg)
                    exit(1001)
            else:
                # ensure slash or backslash is NOT included
                if rsa_key_cache_path[-1:] == '/' or rsa_key_cache_path[-1:] == '\\':
                    rsa_key_cache_path = rsa_key_cache_path[:-1]
                # save
                rsa_key_cache_path = rsa_key_cache_path
        else:
            self.log(30, 'no rsa key cache path found. it needs to be set to send out encrypted messages and to verify signatures.')

        # save
        self.rsa_key_cache_path = rsa_key_cache_path
        self.rsa_pub_key_path = rsa_pub_key_path
        self.rsa_priv_key_path = rsa_priv_key_path
        self.rsa_priv_key_pass = rsa_priv_key_pass
        
        # init
        self.encrypt = False
        self.sign = False

        # import extensions loaded
        for ext in PYOPENSPIME_EXTENSIONS_LOADED:
            exec( 'import pyopenspime.protocol.extension.%s' % ext )

        # create EnDec object
        self.endec = EnDec()
        
        # load keys
        if self.rsa_pub_key_path <> '' and self.rsa_priv_key_path <> '':
            try:
                # check if files exist
                if os.path.isfile(self.rsa_pub_key_path) == False or os.path.isfile(self.rsa_priv_key_path) == False:
                    self.log(20, u'RSA keys do not exist, encryption and digital signature will not be available.')
                else:
                    # load keys
                    self.endec.load_rsa_key_bio(self.rsa_pub_key_path, self.rsa_priv_key_path, self.rsa_priv_key_pass)
                    self.log(20, u'client RSA keys successfully loaded.')
            except:
                msg = u'error (%s) while loading RSA keys: %s.' % (unicode(sys.exc_info()[0].__name__), \
                                                                   unicode(sys.exc_info()[1]))
                self.log(40, msg)
                raise Exception, msg
        else:
            self.endec = None        
        
        # load accepted certified authorities        
        if accepted_cert_authorities_filepath <> '':
            if os.path.isfile(accepted_cert_authorities_filepath) == False:
                msg = u'specified accepted certified authorities file \'%s\' does not exist or cannot be accessed.' % unicode(accepted_cert_authorities_filepath)
                self.log(40, msg)
                raise Exception, msg
            # read
            self.accepted_cert_authorities = []
            f = open(accepted_cert_authorities_filepath, "r" )
            for line in f:
                line = line.strip().replace('\r','').replace('\n','')
                if len(line) > 0 and line[:1] <> '#':
                    self.accepted_cert_authorities.append(line)
            self.log(10, u'accepted certified authorities file successfully read, loaded %d authorities.' % len(self.accepted_cert_authorities))
        else:
            self.accepted_cert_authorities = None

        # log
        self.log(10, u'StanzaInterpreter succesfully initialized.')


    def validate(self, stanza):        
        """
        Check if incoming <message/> and <iq/> stanzas are handled by the OpenSpime protocol.
        
        @type  stanza: pyopenspime.xmpp.protocol.Stanza
        @param stanza: The incoming stanza.
        @rtype:   mixed
        @return:  if successful:    ReqObj():                              the ReqObj of the extension.
                  if error found:   pyopenspime.xmpp.protocol.Protocol:    stanza to be sent out as error.
        """

        # get stanza kind: iq, message, presence
        stanza_kind = stanza.getName().strip().lower()

        # decrypt stanza if necessary
        try:
            stanza = self.decrypt(stanza)
        except DecryptionError:
            # message could not be decrypted
            if stanza_kind == 'iq':
                return Error(stanza, 'modify', 'decryption-error', 'openspime:protocol:core:error', \
                            'the incoming stanza was sent encrypted, though there were errors decrypting it (encrypted with wrong public RSA key?).')
        except MissingPrivateKey:
            # client has no private key to decrypt incoming message
            if stanza_kind == 'iq':
                return Error(stanza, 'cancel', 'decryption-not-enabled', 'openspime:protocol:core:error', \
                            'the incoming stanza was sent encrypted, but the recipient entity is not enabled to decrypt it.')
        except MalformedXML:
            # message could not be decrypted
            if stanza_kind == 'iq':
                return Error(stanza, 'modify', 'xml-malformed-transport-node', 'openspime:protocol:core:error', \
                            'the incoming stanza has been decrypted, but the <transport/> node contains non valid xml.')
        except:
            raise # XXX set to pass in production

        # check stanza signature, if any
        try:
            valid_signature = self.check_signature(stanza)
        except KeyCachePathNotSet:
            # key cache not available
            if stanza_kind == 'iq':
                return Error(stanza, 'cancel', 'signature-not-enabled', 'openspime:protocol:core:error', \
                            'the stanza has a signature, but the recipient entity is not enabled to verify signatures.')
        except SigneeCertifiedPublicKeyNotInCache, SigneeCertifiedPublicKeyCorruptedRetry:
            raise
        except SigneeCertifiedPublicKeyFromUnauthCert:
            # unaccepted cert authority
            if stanza_kind == 'iq':
                return Error(stanza, 'cancel', 'signature-error-invalid-cert-auth', 'openspime:protocol:core:error', \
                            'the stanza is signed by a certification authority which is not accepted by recipient.')            
        except SigneeCertifiedPublicKeyCorrupted:
            # key cache not available
            if stanza_kind == 'iq':
                return Error(stanza, 'cancel', 'signature-error-public-key-corrupted', 'openspime:protocol:core:error', \
                            'the stanza has a signature which could not be validated because the public RSA key of the originator received from the cert authority is corrupted.')
        except MalformedXML:
            # malformed transport node
            if stanza_kind == 'iq':
                return Error(stanza, 'modify', 'xml-malformed-transport-node', 'openspime:protocol:core:error', \
                            'the <transport/> node of the incoming stanza contains non valid xml.')
        except:
            raise # XXX set to pass in production

        # loop available extensions
        for ext in PYOPENSPIME_EXTENSIONS_LOADED:
            self.log(10, u'trying \'%s\' extension for validity' % ext)
            # call extension validate function
            exec( 'result = pyopenspime.protocol.extension.%s.validate(stanza, self)' % ext )
            if result == True:
                # ok we have a match, call core main function                
                self.log(10, u'extension \'%s\' matches, calling main function' % ext)
                exec( 'reqobj = pyopenspime.protocol.extension.%s.main(stanza, self)' % ext )
                self.log(10, u'received \'%s\' extension request object.' % ext)
                return reqobj
            else:           
                self.log(10, u'extension \'%s\' does not match.' % ext)


    def encrypt_and_sign(self, stanza, encrypt=False, sign=False):
        """
        Function that manages encryption and signature of a stanza according to the OpenSpime protocol Core Reference Schema v0.9.

        @type  stanza: pyopenspime.xmpp.protocol.Stanza
        @param stanza: The stanza to be encrypted and signed.
        @type  encrypt: boolean
        @param encrypt: If encryption is requested, set to True. Defaults to I{False}.
        @type  sign: boolean
        @param sign: If signature is requested, set to True. Defaults to I{False}.
            
        @rtype:   pyopenspime.xmpp.simplexml.Node
        @return:  The OpenSpime encrypted and signed stanza.
        """
        
        # get the <openspime/> node
        n_openspime = pyopenspime.util.parse_all_children(stanza, 'openspime')
        
        # check if something needs to be done
        if n_openspime <> None and (encrypt == True or sign == True):
            # get to
            to_osid = str(stanza.getTo())
            if encrypt == True:                
                # if encryption is requested, check that we have the recipient public RSA key
                self.log(10, u'get recipient key from cache')
                to_osid_hex = binascii.b2a_hex(to_osid)
                to_osid_key_path = '%s/%s' % (self.rsa_key_cache_path, to_osid_hex)
                # check that filename 'fromcert' exists
                if os.path.isfile('%s.fromcert' % to_osid_key_path) == True:
                    self.log(10, u'recipient cert key found in cache, using it to encrypt outgoing stanza.')
                    to_osid_key_path = '%s.fromcert' % to_osid_key_path
                elif os.path.isfile(to_osid_key_path) == True:
                    self.log(10, u'recipient non-cert key found in cache, using it to encrypt outgoing stanza.')
                else:
                    # recipient public key is not in cache
                    msg = u'recipient public key not found in cache, cannot encrypt outgoing message.'
                    self.log(30, msg)
                    raise RecipientPublicKeyNotInCache(msg)
            
            # get originator
            originator_osid = pyopenspime.util.get_originator_osid(stanza)
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
                if self.endec == None:
                    raise Exception, 'no rsa keys have been specified for the client, cannot sign openspime message.'                
                # get <originator/> node
                n_originator = pyopenspime.util.parse_all_children(n_openspime, 'originator')
                if n_originator <> None:
                    originator_osid = pyopenspime.util.get_originator_osid(stanza)
                else:
                    # create node
                    n_originator = n_transport.addChild(name=u'originator')
                # add cert authority
                if self.cert_authority <> '':
                    n_originator.setAttr('cert', self.cert_authority)
                else:
                    raise Exception, 'no cert authority has been set for client, cannot sign openspime message.'  
                self.log(10, u'computing signature')
                signature = self.endec.private_sign(transport_child_content)
                self.log(10, u'adding signature node')
                n_sign = n_originator.addChild(name=u'sign')
                n_sign.addData(signature)
            
            # encrypt
            if encrypt == True:
                self.log(10, u'adding <transport/> node \'content-type\' encrypted attribute')
                n_transport.setAttr('content-type', 'x-openspime/aes-base64')                
                # encrypt content
                self.log(10, u'loading public RSA key of recipient')
                endec = EnDec()
                endec.load_rsa_pub_key(to_osid_key_path)
                self.log(10, u'encrypting')
                encrypted = endec.public_encrypt(transport_child_content)
                n_transport = pyopenspime.util.clean_node(n_transport)
                n_transport.setData(encrypted[0])
                n_transport.setAttr('transport-key', encrypted[1])
        
        # return
        return stanza
        
    def decrypt(self, stanza):
        """
        Function that manages decryption of an OpenSpime stanza according to the OpenSpime protocol Core Reference Schema v0.9.
        
        @type  stanza: pyopenspime.xmpp.protocol.Stanza
        @param stanza: The stanza to be decrypted.
            
        @rtype:   pyopenspime.xmpp.simplexml.Node
        @return:  The <openspime/> decrypted stanza node.
        """

        # check if decryption is needed, look for the <transport/> element
        self.log(10, u'check if decryption is needed, get <transport/> node')
        n_transport = pyopenspime.util.parse_all_children(stanza, 'transport')

        if n_transport <> None:
            # get encoding
            self.log(10, u'check encoding of incomed stanza')
            attr = n_transport.getAttr('content-type')
            if attr == 'x-openspime/aes-base64':
                self.log(10, u'received message is encrypted.')
                
                # check that client can decrytpt
                if self.endec == None:
                    msg = u'incoming stanza is encrypted but no rsa key has been specified to decrypt it.'
                    self.log(40, msg)
                    raise MissingPrivateKey(msg)
                
                # content is encrypted -> get transport-key                
                self.log(10, u'get transport-key')
                attr_transport_key = n_transport.getAttr('transport-key')
                # decrypt
                try:
                    self.log(10, u'trying to decrypt')
                    decrypted_content = self.endec.private_decrypt(n_transport.getData(), attr_transport_key)
                except:
                    msg = u'received message could not be decrypted.'
                    self.log(40, msg)
                    raise DecryptionError(msg)
                self.log(10, u'message has succesfully been decrypted.')
                # parse
                try:
                    # empty node
                    self.log(10, u'substituting content of <transport/> node')
                    n_transport = pyopenspime.util.clean_node(n_transport)
                    # create transport child
                    n_transport_child = pyopenspime.xmpp.simplexml.Node(node=decrypted_content)
                    # add decrypted content to the <transport/> node
                    n_transport.addChild(node=n_transport_child)
                    # remove "content-type" and "transport-key" attributes of <transport/> node
                    n_transport.delAttr('content-type')
                    n_transport.delAttr('transport-key')
                except:
                    msg = u'malformed <transport/> xml node in received message.'
                    self.log(40, msg)
                    raise MalformedXML(msg)
        else:
            self.log(10, u'no decryption needed.')

        # return decrypted stanza
        return stanza


    def check_signature(self, stanza):
        """
        Function that checks signature of an OpenSpime stanza according to the OpenSpime protocol Core Reference Schema v0.9.
        
        @type  stanza: pyopenspime.xmpp.protocol.Stanza
        @param stanza: The stanza to be checked.
            
        @rtype:   boolean
        @return:  True if signature is valid or stanza not signed, otherwise raises errors.
        """
        
        # check if signature has been provided, look for the <originator/> element
        self.log(10, u'checking if signature has been provided, look for the <originator/> node')
        n_originator = pyopenspime.util.parse_all_children(stanza, 'originator')
        # loop children
        n_sign = None
        if n_originator <> None:
            for child in n_originator.getChildren():
                if child.getName() == 'sign':
                    # set sign node
                    n_sign = child
                    self.log(10, u'signature found.')

                    # check that client has a rsa_key_cache_path
                    if self.rsa_key_cache_path == '':
                        msg = u'incoming stanza is signed but no cache path has been specified to download signee public key from cert authority.'
                        self.log(40, msg)
                        raise KeyCachePathNotSet(msg)

                    # check that certification authority is accepted
                    osid_cert = pyopenspime.util.get_cert_osid(stanza)
                    if not osid_cert in self.accepted_cert_authorities:
                        msg = u'incoming stanza is signed from an unaccepted certification authority: <%s>.' % osid_cert
                        self.log(40, msg)
                        raise SigneeCertifiedPublicKeyFromUnauthCert(msg)
                        
                    # get originator
                    originator_osid = pyopenspime.util.get_originator_osid(stanza)
                    # check if public key of originator is in cache
                    self.log(10, u'checking if originator certified public rsa key is in cache')
                    originator_osid_hex = binascii.b2a_hex(originator_osid)
                    originator_key_fromcert_path = '%s/%s.fromcert' % (self.rsa_key_cache_path, originator_osid_hex)
                    # check that filename 'fromcert' exists
                    if os.path.isfile(originator_key_fromcert_path) == False:
                        msg = u'incoming stanza is signed but the signee certified public key could not be found in cache.'
                        self.log(40, msg)
                        raise SigneeCertifiedPublicKeyNotInCache(msg)

                    # create endec object
                    endec = EnDec()
                    try:
                        self.log(10, u'loading originator public RSA key')
                        endec.load_rsa_pub_key(originator_key_fromcert_path)
                    except:           
                        # check time of fromcert public RSA key
                        sign_info = os.stat(originator_key_fromcert_path)
                        if time.time() - sign_info.st_mtime > 200:
                            msg = u'error loading originator public rsa key, requesting newer key to certification authority.'
                            self.log(40, msg)
                            raise SigneeCertifiedPublicKeyCorruptedRetry(msg)
                        else:
                            # key corrupted
                            msg = u'originator public certified RSA key corruped, signature cold not be verified, incoming stanza will be ignored.'
                            self.log(40, msg)
                            raise SigneeCertifiedPublicKeyCorrupted(msg)
                    # get signature                
                    self.log(10, u'reading signature')
                    signature = child.getData()
                    n_transport = pyopenspime.util.parse_all_children(stanza, 'transport')
                    try:
                        content = n_transport.getChildren()[0]
                    except:                        
                        msg = u'the <transport/> node of the incoming stanza contains non valid xml.'
                        self.log(40, msg)
                        raise MalformedXML(msg)

                    # check
                    self.log(10, u'verifying signature')
                    if endec.public_check_sign(content, signature) == True:
                        self.log(10, u'signature was succesfully verified.')
                    else:              
                        # check time of fromcert public RSA key
                        sign_info = os.stat(originator_key_fromcert_path)
                        if time.time() - sign_info.st_mtime > 200:
                            msg = u'error loading originator public rsa key, requesting newer key to certification authority.'
                            self.log(40, msg)
                            raise SigneeCertifiedPublicKeyCorruptedRetry(msg)
                        else:
                           # key corrupted
                            msg = u'originator public certified RSA key corruped, signature cold not be verified, incoming stanza will be ignored.'
                            self.log(40, msg)
                            raise SigneeCertifiedPublicKeyCorrupted(msg)
                    break
        return True
    

    def get_error(self, stanza):
        """
        Retrieves error condition and description from an error stanza.
        Reference is OpenSpime protocol Core Reference Schema v0.9.
        @rtype:   Dictionary
        @return:  Dictionary containing:
                                    error_cond
                                    error_description
        """
        return Error(stanza=stanza).get_error()
    

    def create_xmpp_error(self, stanza, error, error_type='modify'): 
        """
        Retrieves error condition and description from an error stanza.
        Reference is XMPP RFC 3920.
        
        @rtype:   pyopenspime.xmpp.protocol.Error
        @return:  Error stanza
        """
        return pyopenspime.xmpp.protocol.Error(node=stanza, error=error)

    
    ###### Support functions
    def log(self, level, msg):
        """
        Logging function triggered on log messages.
        Uses the same syntax of logger.Logger.append()
        """
        pass





























