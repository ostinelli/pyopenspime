#
# PyOpenSpime - Client Module
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

"""PyOpensPime Client Module."""

# imports
import sys, locale, codecs, time
from pyopenspime.engine import *
import pyopenspime.xmpp, pyopenspime.util, pyopenspime.protocol.extension.xmpp.pubkey


class Client(pyopenspime.xmpp.Client):
    """
    PyOpenSpime XMPP Client
    """
    
    def __init__(self, osid_or_osid_path, osid_pass='', server='', port=5222, try_reconnect=60, rsa_pub_key_path='', rsa_priv_key_path='', rsa_priv_key_pass='', rsa_key_cache_path='cache', \
                 cert_authority='', accepted_cert_authorities_filepath='certification-authorities.conf', log_callback_function=None):
        """
        Initializes a Client.
        
        @type  osid_or_osid_path: str
        @param osid_or_osid_path: The full OSID of the client. If an OpenSpime configuration package is found, this is
            the only parameter that is needed to initialize the Client.
        @type  osid_pass: str
        @param osid_pass: The full OSID password. I{Taken from the OpenSpime configuration package if found}.
        @type  server: str
        @param server: The server address. Defaults to the OSID domain.
        @type  port: int
        @param port: The server port. Defaults to I{5222}.
        @type  try_reconnect: int
        @param try_reconnect: Reconnects if connection drops. Set to 0 if no reconnect, otherwise integer expresses
            interval to reconnection trials in seconds. Defaults to I{60}.
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
        
        # XMPP protocol is unicode-based. convert output format to local encoding to avoid UnicodeException error.
        locale.setlocale(locale.LC_CTYPE,"")
        encoding = locale.getlocale()[1]
        if not encoding:
            encoding = "us-ascii"
        sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors = "replace")
        sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors = "replace")
        
        # set log callback function
        if log_callback_function != None:
            self.log = log_callback_function
                
        # try to get openspime package
        ospackage_info = pyopenspime.util.OsPackage(osid_or_osid_path, self.log).read()
        if ospackage_info <> None:
            # get values from package if nothing has been forced in init params
            if osid_pass == '': osid_pass = ospackage_info['osid_pass']
            if server == '': server = ospackage_info['server']
            if port == '': port = ospackage_info['port']
        
        # save
        self.osid = pyopenspime.xmpp.JID(osid_or_osid_path)
        self.osid_pass = osid_pass
        
        # get server if not explicitely stated
        if server == None:
            server = self.osid.getDomain()                
        self.Server = server
        self.Port = port
        
        # init
        self.timeout = 60
        self.__trying_reconnection = False
        self.connected = False
        self.encrypt = False
        self.sign = False
        self.log(10, u'default security set to: encrypt=%s, sign=%s' % (self.encrypt, self.sign))
        self.__iq_callback_handlers = {}
        self.__awaiting_stanzas_to_be_sent = {}
        self.__awaiting_stanzas_to_be_treated = {}
        
        # save
        if isinstance(try_reconnect, int) == False:
            self.log(40, 'reconnect must be expressed as integer.')
            exit(1002)
        self.try_reconnect = try_reconnect

        # init StanzaInterpreter
        self.__stanza_interpreter = StanzaInterpreter(osid_or_osid_path, rsa_pub_key_path, rsa_priv_key_path, rsa_priv_key_pass, rsa_key_cache_path, cert_authority, accepted_cert_authorities_filepath, \
                                                      log_callback_function)
        
        # init component
        self.Namespace, self.DBG = 'jabber:client', 'client' # check lines: 99 & 101 of xmpp.client 
        pyopenspime.xmpp.Client.__init__(self, self.osid.getDomain(), port, [])
        
        self.log(20, u'client succesfully initialized.')

    
    def __setattr__(self, name, value):        
        # set default
        self.__dict__[name] = value

        
    def __presence_handler(self, dispatcher, stanza):
        # handles PRESENCE stanzas        
        pass

    
    def __message_handler(self, dispatcher, stanza):
        # handles MESSAGE stanzas        
        return self.__iq_and_message_common(stanza)

    
    def __iq_handler(self, dispatcher, stanza):
        # handles IQ stanzas - MUST return True if stanza is handled, False if not so that 'feature-not-implemented' is sent back as response by xmpppy

        ##### print "INCOMING STANZA: " + str(stanza)
        
        iq_from = unicode(stanza.getFrom())
        iq_id = stanza.getID()
        iq_type = stanza.getType().lower()
        self.log(10, u'received iq from <%s>.' % (iq_from))
        # check if incoming IQ is a response to a done request
        self.log(10, u'check if incoming <iq/> stanza is a response to a done request')
        if iq_type == 'result' or iq_type == 'error':
            if self.__iq_callback_handlers.has_key(iq_id) == True:
                if iq_type == 'result':
                    # callback ok
                    if self.__iq_callback_handlers[iq_id][1] <> None:
                        self.log(10, u'calling the success callback handler')
                        self.__iq_callback_handlers[iq_id][1](stanza, self.__iq_callback_handlers[iq_id][0])
                    else:
                        self.log(10, u'no success callback available.')
                    # send the associated awaiting stanza to be sent, if any
                    if self.__awaiting_stanzas_to_be_sent.has_key(iq_id) == True:
                        self.log(10, u'sending the associated awaiting stanza')
                        self.send_stanza(self.__awaiting_stanzas_to_be_sent[iq_id][0], self.__awaiting_stanzas_to_be_sent[iq_id][1], self.__awaiting_stanzas_to_be_sent[iq_id][2], \
                                         self.__awaiting_stanzas_to_be_sent[iq_id][3], self.__awaiting_stanzas_to_be_sent[iq_id][4], self.__awaiting_stanzas_to_be_sent[iq_id][5], \
                                         self.__awaiting_stanzas_to_be_sent[iq_id][6], self.__awaiting_stanzas_to_be_sent[iq_id][7], self.__awaiting_stanzas_to_be_sent[iq_id][8])
                    # treat the associated awaiting stanza to be treated, if any
                    if self.__awaiting_stanzas_to_be_treated.has_key(iq_id) == True:
                        awaiting_stanza = self.__awaiting_stanzas_to_be_treated[iq_id][0]
                        del self.__awaiting_stanzas_to_be_treated[iq_id]      
                        self.log(10, u'associated awaiting stanza to be treated key removed.')
                        self.log(10, u'treating the associated awaiting stanza')
                        self.treat_stanza(awaiting_stanza)
                if iq_type == 'error':
                    # callback ko
                    if self.__iq_callback_handlers[iq_id][2] <> None:
                        self.log(10, u'calling the failure callback handler')
                        self.__iq_callback_handlers[iq_id][2](stanza, self.__iq_callback_handlers[iq_id][0])
                    else:
                        self.log(10, u'no failure callback available.')
                    # treat the associated awaiting stanza to be treated, if any
                    if self.__awaiting_stanzas_to_be_treated.has_key(iq_id) == True:
                        self.log(10, u'treating the associated awaiting stanza, sending <internal-server-error> error')
                        self.send_stanza( self.__stanza_interpreter.create_xmpp_error(self.__awaiting_stanzas_to_be_treated[iq_id][0], 'internal-server-error'), \
                                          self.__awaiting_stanzas_to_be_treated[iq_id][0].getFrom() )
                        del self.__awaiting_stanzas_to_be_treated[iq_id] 
                        self.log(10, u'associated awaiting stanza to be treated key removed.') 
                # free key
                del self.__iq_callback_handlers[iq_id]
                self.log(10, u'callback handler key removed.')
                # free associated awaiting stanza to be sent, if any
                if self.__awaiting_stanzas_to_be_sent.has_key(iq_id) == True:
                    del self.__awaiting_stanzas_to_be_sent[iq_id]      
                    self.log(10, u'associated awaiting stanza to be sent key removed.')
                # exit
                return True
            else:
                self.log(10, u'incoming <iq/> stanza is not a reponse to a done request, ignoring.')
        else:
            self.log(10, u'incoming <iq/> stanza is not a reponse to a done request, calling interpreter.')
            # incominq IQ is not a response to a done request, get response from stanza interpreter
            result = self.__iq_and_message_common(stanza)
            # return
            return result


    def __iq_and_message_common(self, stanza):
        # handles common part of IQ and MESSAGE stanzas

        # get handler [stanza, reqobj, or errors may be raised]
        try:
            handler = self.__stanza_interpreter.validate(stanza)
        except SigneeCertifiedPublicKeyNotInCache, SigneeCertifiedPublicKeyCorruptedRetry:
            # signee certified public key not found in cache, we need to request it before proceeding
            self.log(10, u'signee certified public key not found in cache, we need to request it before proceeding')
            # get cert authority
            osid_cert = pyopenspime.util.get_cert_osid(stanza)
            # request key
            pubkey_reqobj = pyopenspime.protocol.extension.xmpp.pubkey.ReqObj(stanza.getFrom())
            awaiting_stanza_iq_trigger_id = self.send_request(pubkey_reqobj, osid_cert)
            self.log(10, u'public key request sent to certification authority <%s>.' % osid_cert)
            # save current stanza to be treated
            self.__save_awaiting_stanza_to_be_treated(awaiting_stanza_iq_trigger_id, stanza)
            self.log(10, u'awaiting stanza to be treated saved with iq trigger id \'%s\'.' % awaiting_stanza_iq_trigger_id)  
            return True
        except:
            raise # should be set to pass in production

        # dispatch 
        if isinstance(handler, pyopenspime.xmpp.protocol.Protocol) == True:
            # send stanza
            self.send_stanza(handler, handler.getTo())
        if hasattr(handler, 'extname') == True:
            # incoming request extension found, call event
            return self.__on_request_received(handler)

        
    def __iq_callback_timeout(self):
        # handles timeout of callback handlers
        
        # loop all keys of __iq_callback_handlers dictionary
        for key in self.__iq_callback_handlers:
            if self.__iq_callback_handlers[key][4] < time.time():
                # timeout
                self.log(10, u'timeout waiting for reponse on <iq/> stanza with id \'%s\'.' % key)
                # callback
                if self.__iq_callback_handlers[key][3] <> None:
                    self.log(10, u'calling the timeout callback handler')
                    self.__iq_callback_handlers[key][3](key, self.__iq_callback_handlers[key][0])
                else:
                    self.log(10, u'no timeout handler available.')    
                # free key
                del self.__iq_callback_handlers[key]    
                self.log(10, u'callback handler key removed.')
                # free associated awaiting stanza to be sent, if any
                if self.__awaiting_stanzas_to_be_sent.has_key(key) == True:
                    del self.__awaiting_stanzas_to_be_sent[key]          
                    self.log(10, u'associated awaiting stanza to be sent\'s key removed.')  
                # treat the associated awaiting stanza to be treated, if any
                if self.__awaiting_stanzas_to_be_treated.has_key(key) == True:
                    self.log(10, u'treating the associated awaiting stanza, sending <remote-server-timeout> error')
                    self.send_stanza( self.__stanza_interpreter.create_xmpp_error(self.__awaiting_stanzas_to_be_treated[key][0], 'remote-server-timeout'), \
                                      self.__awaiting_stanzas_to_be_treated[key][0].getFrom() )              
                    # free associated awaiting stanza to be treated
                    del self.__awaiting_stanzas_to_be_treated[key]      
                    self.log(10, u'associated awaiting stanza to be treated\'s key removed.')
                break

        # loop all keys of __awaiting_stanzas_to_be_sent dictionary
        # NOTICE: this is only necessary in case of errors in setting the awaiting_stanza_iq_trigger_id 
        for key in self.__awaiting_stanzas_to_be_sent:
            if self.__awaiting_stanzas_to_be_sent[key][9] < time.time():
                # free key
                del self.__awaiting_stanzas_to_be_sent[key]
                self.log(10, u'timeout waiting for reponse on <iq/> stanza with id \'%s\', the associated awaiting stanza to be sent has been removed.' % key)
                break

        # loop all keys of __awaiting_stanzas_to_be_treated dictionary
        # NOTICE: this is only necessary in case of errors in setting the awaiting_stanza_iq_trigger_id 
        for key in self.__awaiting_stanzas_to_be_treated:
            if self.__awaiting_stanzas_to_be_treated[key][1] < time.time():
                # free key
                del self.__awaiting_stanzas_to_be_treated[key]
                self.log(10, u'timeout waiting for reponse on <iq/> stanza with id \'%s\', the associated awaiting stanza to be treated has been removed.' % key)
                break


    def __on_request_received(self, reqobj):
        """
        Called when an OpenSpime extension request has been received.
        """
        
        if reqobj.extname == 'xmpp.pubkey':
            # accept incoming request, send key
            self.send_response(reqobj.accepted())
            # extension has been treated, return True
            return True
        # if not an xmpp.pubkey request, let the derived client handle it
        return self.on_request_received(reqobj)


    def on_request_received(self, reqobj):
        """
        Event fired upon OpenSpime request received. MUST return True if stanza is handled, False if not so that a 'feature-not-implemented' error is sent back as response.
        This one does nothing, should be overriden in derived classes.
        """
        pass


    def on_response_success(self, stanza_id, stanza):       
        """
        Event raised on successful request. This one does nothing, should be overriden in derived classes.
        """
        pass
    

    def on_response_failure(self, stanza_id, error_cond, error_description, stanza):     
        """
        Event raised on failure on request. This one does nothing, should be overriden in derived classes.
        """
        pass


    def on_response_timeout(self, stanza_id):      
        """
        Event raised on timeout waiting a response to a request. This one does nothing, should be overriden in derived classes.
        """
        pass


    def __iq_on_success(self, stanza, extname):
        # handles callbacks to extension in case of success, otherwise defaults to self.on_response_status

        # create reqobj to call reqobj events
        try:
            exec( "reqobj = pyopenspime.protocol.extension.%s.ReqObj('%s')" % (extname, stanza.getName().strip().lower()) )
            reqobj.stanza_interpreter = self.__stanza_interpreter
        except:
            reqobj = None
        launch_event = True
        # launch reqobj events
        if hasattr(reqobj, 'on_success'):
            launch_event = reqobj.on_success(stanza)
        # launch event if not blocked by reqobj events
        if launch_event == True:
            self.on_response_success(stanza.getID(), stanza)
        

    def __iq_on_failure(self, stanza, extname):
        # handles callbacks to extension in case of failure, otherwise defaults to self.on_response_status

        # create reqobj to call reqobj events
        try:
            exec( "reqobj = pyopenspime.protocol.extension.%s.ReqObj('%s')" % (extname, stanza.getName().strip().lower()) )
            reqobj.stanza_interpreter = self.__stanza_interpreter
        except:
            reqobj = None
        launch_event = True
        # launch reqobj events
        if hasattr(reqobj, 'on_failure'):
            launch_event = reqobj.on_failure(stanza)
        # launch event if not blocked by reqobj events
        if launch_event == True:
            # get error desc
            error = self.__stanza_interpreter.get_error(stanza)
            self.on_response_failure(stanza.getID(), error['error_cond'], error['error_description'], stanza)


    def __iq_on_timeout(self, stanza_id, extname):
        # handles callbacks to extension in case of timeout, otherwise defaults to self.on_response_status

        # create reqobj to call reqobj events
        try:
            exec( "reqobj = pyopenspime.protocol.extension.%s.ReqObj('%s')" % (extname, stanza.getName().strip().lower()) )
            reqobj.stanza_interpreter = self.__stanza_interpreter
        except:
            reqobj = None
        launch_event = True
        # launch reqobj events
        if hasattr(reqobj, 'on_timeout'):
            launch_event = reqobj.on_timeout(stanza_id)
        # launch event if not blocked by reqobj events
        if launch_event == True:
            self.on_response_timeout(stanza_id)


    def __save_awaiting_stanza_to_be_sent(self, awaiting_stanza_iq_trigger_id, stanza, to_osid='', encrypt=None, sign=None, extname='', \
                               callback_success=None, callback_failure=None, callback_timeout=None, timeout=60):
        # save information on stanza waiting to be sent that will be triggered when a successful response IQ with id awaiting_stanza_iq_trigger_id is received.
        
        self.__awaiting_stanzas_to_be_sent[awaiting_stanza_iq_trigger_id] = (stanza, to_osid, encrypt, sign, extname, callback_success, callback_failure, callback_timeout, timeout, time.time() + timeout)
        self.log(10, u'current stanza to be sent has been saved.')

        
    def __save_awaiting_stanza_to_be_treated(self, awaiting_stanza_iq_trigger_id, stanza, timeout=60):
        # save information on stanza waiting to be treated that will be triggered when a successful response IQ with id awaiting_stanza_iq_trigger_id is received.
        
        self.__awaiting_stanzas_to_be_treated[awaiting_stanza_iq_trigger_id] = (stanza, time.time() + timeout)
        self.log(10, u'current stanza to be sent has been saved.')


    def send_request(self, reqobj, to_osid, encrypt=None, sign=None):
        """
        Function to send out OpenSpime requests.
        """
        return self.send_stanza(reqobj.build(), to_osid, encrypt, sign, reqobj.extname, self.__iq_on_success, self.__iq_on_failure, self.__iq_on_timeout)


    def send_response(self, stanza, encrypt=None, sign=None):       
        """
        Function to send out OpenSpime responses.
        """
        return self.send_stanza(stanza=stanza, encrypt=encrypt, sign=sign)


    def send_stanza(self, stanza, to_osid='', encrypt=None, sign=None, extname='', callback_success=None, callback_failure=None, callback_timeout=None, timeout=60):
        """
        Sends out a stanza.
        
        @type  stanza: pyopenspime.xmpp.protocol.Protocol
        @param stanza: The stanza to be sent.
        @type  to_osid: unicode
        @param to_osid: The recipient of the message. 
        @type  encrypt: boolean
        @param encrypt: If encryption is requested, set to True. Defaults to I{False}.
        @type  sign: boolean
        @param sign: If signature is requested, set to True. Defaults to I{False}.
        @type  extname: str
        @param extname: If stanza is representative of a request, the extension name of the request send out.
        @type  callback_success: function
        @param callback_success: Callback function called when a 'result' response is received.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.
        @type  callback_failure: function
        @param callback_failure: Callback function called when a 'error' response is received.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.
        @type  callback_timeout: function
        @param callback_timeout: Callback function called when no response is received after the timeout period.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.
        @type  timeout: int
        @param timeout: If a callback_timeout function has been specified, this parameter specifies the timeout in seconds
            after which the callback_timeout function is called if no response is received. This parameter
            also specifies the time life of the callback_success and callback_failure functions, after which their 
            handler will be removed.
            This parameter is ignored if the stanza being sent is not an <iq/> stanza.
        
        @rtype:   unicode
        @return:  ID of sent stanza.
        """
        
        if self.connected == False:
            msg = u'client is not connected, could not send message.'
            self.log(40, msg)
            raise Exception, msg

        # set defaults
        if encrypt == None: encrypt = self.encrypt
        if sign == None: sign = self.sign
        self.log(10, u'stanza security: encrypt=%s, sign=%s' % (encrypt, sign))

        # 'from' and 'to' attributes
        stanza.setFrom(self.osid)
        if to_osid <> '': stanza.setTo(to_osid)

        # serialize ID if necessart
        ID = stanza.getID()
        if ID == None:
            # serialize id
            ID = self.serialize()
            stanza.setID(ID)

        # encrypt and sign
        try:
            stanza = self.__stanza_interpreter.encrypt_and_sign(stanza, encrypt, sign)
        except RecipientPublicKeyNotInCache:
            # recipient public key not found in cache, we need to request it before proceeding
            self.log(10, u'recipient public key not found in cache, we need to request it before proceeding')
            # request key
            pubkey_reqobj = pyopenspime.protocol.extension.xmpp.pubkey.ReqObj(stanza.getTo())
            awaiting_stanza_iq_trigger_id = self.send_request(pubkey_reqobj, stanza.getTo())
            self.log(10, u'public key request sent to <%s>.' % stanza.getTo())
            # save current outgoing stanza
            self.__save_awaiting_stanza_to_be_sent(awaiting_stanza_iq_trigger_id, stanza, to_osid, encrypt, sign, extname, callback_success, callback_failure, callback_timeout, timeout)
            self.log(10, u'awaiting stanza to be sent saved with iq trigger id \'%s\'.' % awaiting_stanza_iq_trigger_id)  
            # put outgoing stanza on hold
            stanza = None              
        except:
            raise

        if stanza <> None:
            # add iq handlers
            if stanza.getName().strip().lower() == 'iq':
                if (stanza.getType() == 'set' or stanza.getType() == 'get'):
                    # add key
                    self.log(10, u'creating callback handler for outgoing stanza')
                    self.__iq_callback_handlers[ID] = (extname, callback_success, callback_failure, callback_timeout, time.time() + timeout)
            # send
            self.log(10, u'sending stanza with ID \'%s\'' % ID)
            self.Dispatcher.send(stanza)

            ##### print "OUTGOING STANZA: " + str(stanza)
        
        # return id
        return ID


    def treat_stanza(self, stanza):
        """
        Treats a manually added stanza.
        
        @type  stanza: pyopenspime.xmpp.protocol.Protocol
        @param stanza: The stanza to be sent.
        """

        # get stanza kind: iq, message, presence
        stanza_kind = stanza.getName().strip().lower()
        if stanza_kind == 'iq':
            self.__iq_handler(self.Dispatcher, stanza)
        elif stanza_kind == 'message':
            self.__message_handler(self.Dispatcher, stanza)
        elif stanza_kind == 'presence':
            self.__presence_handler(self.Dispatcher, stanza)

        
    def __reconnect(self):        
        # reconnect client
        
        try:
            self.__handlerssave = self.Dispatcher.dumpHandlers()
            self.log(10, 'handlers dumped.')
            if self.__dict__.has_key('ComponentBind'): self.ComponentBind.PlugOut()
            if self.__dict__.has_key('Bind'): self.Bind.PlugOut()
            self._route=0
            if self.__dict__.has_key('NonSASL'): self.NonSASL.PlugOut()
            if self.__dict__.has_key('SASL'): self.SASL.PlugOut()
            if self.__dict__.has_key('TLS'): self.TLS.PlugOut()
            self.Dispatcher.PlugOut()
            self.log(10, 'dispatcher plugged out.')
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
            self.log(10, 'reconnected.')
            self.__trying_reconnection = False
        except:
            self.log(30, 'error while reconnecting, retrying in %s seconds.' % self.try_reconnect)
            time.sleep(self.try_reconnect)
            self.__reconnect()

            
    ###### Events functions
            
    def DisconnectHandler(self):        
        """
        Handler to manage automatic reconnection.
        """
        
        # set connection status
        self.connected = False
        # raise event
        self.on_disconnect()
        if self.__trying_reconnection == False and self.try_reconnect > 0:
            self.__trying_reconnection = True
            self.log(30, 'client is disconnected, trying automatic reconnection immediately then every %s seconds.' % self.try_reconnect)
            self.__reconnect()


    def __on_disconnect(self):
        self.log(30, u'client <%s> was disconnected from the XMPP server.' % self.osid)
        self.on_disconnect()


    def on_disconnect(self):        
        """
        Event raised on a disconnection to the XMPP server. This one does nothing, should be overriden in
        derived classes.

        Note that reconnection attempts are handled automatically, therefore any blocking on_disconnect() derived function will therefore
        compromise such attempts.
        """
        
        pass


    def __on_connect(self):
        self.log(20, u'client <%s> ready.' % self.osid)
        self.on_connect()

    
    def on_connect(self):        
        """
        Event raised on a successful connection to the XMPP server. This one does nothing, should be overriden in
        derived classes.
        """
        
        pass
    
    
    ###### Commlink functions

    def on_timer(self):
        """
        Called periodically every interval of seconds specified by the run() function. This one does nothing, should be overriden in
        derived classes.
        """
        
        pass

    
    def connect(self):
        """
        Connects the Client to the server and initializes handlers.
        """
        
        # connect
        self.log(20, u'connecting to <%s>' % unicode(self.Server))
        if pyopenspime.xmpp.Client.connect(self) == "":
            msg = u'could not connect to server <%s>, aborting.' % unicode(self.Server)
            self.log(40, msg)
            raise Exception, msg
        self.log(10, u'connected.')
        
        # authenticate
        self.log(20, u'authenticating client on server')
        if pyopenspime.xmpp.Client.auth(self, self.osid.getNode(), self.osid_pass, self.osid.getResource()) == None:
            msg = u'could not authenticate, aborting. check osid and password.'
            self.log(40, msg)
            raise Exception, msg
        self.log(10, u'authenticated.')
        
        # notify presence
        self.log(10, u'notifying presence')
        self.sendInitPresence(0)
        
        # register handlers
        self.log(10, u'registering presence handler')
        self.RegisterHandler('presence', self.__presence_handler)
        self.log(10, u'registering message handler')
        self.RegisterHandler('message', self.__message_handler)
        self.log(10, u'registering iq handler')
        self.RegisterHandler('iq', self.__iq_handler)
        
        # set connection status & raise event
        self.connected = True
        self.__on_connect()


    def run(self, timer=0, threaded=True):
        """
        Core running loop.
        
        @type  timer: int
        @param timer: Specifies the seconds interval at which the function on_timer() is called in the client. Defaults to 0 (i.e. on_timer() is never called).
        """
        def connect():
            self.connect()
        
        def runloop():
            t = 0
            while self.loop():
                t += 1
                if t > timer and timer > 0:
                    self.log(10, 'calling timer')
                    self.on_timer()
                    t = 0
                pass
        # threading
        if threaded == True:
            import threading
            class OpenSpimeRunThread(threading.Thread):
                def run(self):
                    connect()
                    runloop()
            OpenSpimeRunThread().start()
        else:
            connect()
            runloop()


    def loop(self, delay=1):
        
        # Main listening loop for the client. Handles events.
        # 
        # @type  delay: int
        # @param delay: delay in seconds between loops
                
        try:
            result = self.Process(delay)
        except:
            self.log(40, "error (%s) while looping: %s" % (sys.exc_info()[0].__name__, sys.exc_info()[1]) )
            raise
        if result == True:
            self.log(30, u'incoming malformed xml, ignored.') 
        # handle iq callback timeout
        self.__iq_callback_timeout()
        if self.connected == True:
            return True # to be used in a while client.loop(1): iterator
        else:
            return False
 
    
    def serialize(self):
        # serializes a stanza ID
        return pyopenspime.util.generate_rnd_str(16)

    
    def closeconnection(self):
        """
        Disconnects from server and handles all incoming stanzas before closure.
        """
        self.try_reconnect = 0
        self.disconnect()  
        self.log(20, u'disconnected.')  

    
    ###### Support functions
    def log(self, level, msg):
        """
        Logging function triggered on log messages.
        Uses the same syntax of logger.Logger.append()
        """
        pass
    


