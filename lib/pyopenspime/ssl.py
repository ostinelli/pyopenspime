#
# PyOpenSpime - SSL Module
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

"""PyOpensPime SSL Module."""

# imports
import binascii, sha
import M2Crypto.RSA, M2Crypto.BIO
import pyopenspime.xmpp, pyopenspime.util


class EnDec():
    """
    Encrypter-Decrypted object.
    This object is used to encrypt, descrypt and sign OpenSpime stanzas. It includes RSA and AES support as
    defined in the OpenSpime Core Protocol v0.9.
    """
    
    def __init__(self):
        """
        Initialize an EnDec object.
        """
        
        self.rsa_pub_key_path = ''
        self.rsa_pub_key = None 
        self.rsa_priv_key_path = ''
        self.rsa_priv_key_pass = ''
        self.rsa_priv_key = None

    def load_rsa_key_bio(self, rsa_pub_key_path, rsa_priv_key_path, rsa_priv_key_pass):
        """
        Load public and private RSA key from .pem files.
        
        @type  rsa_pub_key_path: unicode
        @param rsa_pub_key_path: The path to the RSA public key .pem file.
        @type  rsa_priv_key_path: unicode
        @param rsa_priv_key_path: The path to the RSA private key .pem file.
        @type  rsa_priv_key_pass: unicode
        @param rsa_priv_key_pass: The RSA private key .pem file password.
        """

        self.load_rsa_pub_key(rsa_pub_key_path)
        self.load_rsa_priv_key(rsa_priv_key_path, rsa_priv_key_pass)
        
    def load_rsa_pub_key(self, rsa_pub_key_path):
        """
        Load public RSA key from .pem file.
        
        @type  rsa_pub_key_path: unicode
        @param rsa_pub_key_path: The path to the RSA public key .pem file.
        """
        
        self.rsa_pub_key_path = rsa_pub_key_path
        self.rsa_pub_key = M2Crypto.RSA.load_pub_key(rsa_pub_key_path)
    
    def load_rsa_priv_key(self, rsa_priv_key_path, rsa_priv_key_pass):  
        """
        Load private RSA key from .pem file.
        
        @type  rsa_priv_key_path: unicode
        @param rsa_priv_key_path: The path to the RSA private key .pem file.
        @type  rsa_priv_key_pass: unicode
        @param rsa_priv_key_pass: The RSA private key .pem file password.
        """      

        self.rsa_priv_key_path = rsa_priv_key_path
        # convert to string -> M2Crypto needs str not unicode
        self.rsa_priv_key_pass = pyopenspime.util.to_utf8(rsa_priv_key_pass)
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
        # get priv_key size
        s = int(self.rsa_priv_key.__len__() / 8)
        decrypted = []
        # chunk decrypt
        for i in range(0, len(encrypted), s):
            decrypted.append(self.rsa_priv_key.private_decrypt(encrypted[i:i+s], M2Crypto.RSA.pkcs1_padding))
        # return
        return ''.join(decrypted)
    
    def __rsa_private_encrypt_base64(self, plaintext):
        
        # RSA private encryption
        
        # get priv_key size
        s = int(( self.rsa_priv_key.__len__() ) / 8) - 11    # take away 11 bytes due to pkcs1_padding
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

    def private_encrypt_text(self, plaintext):
        """
        Encrypts plaintext with the RSA private key of entity.
        
        @type  plaintext: str
        @param plaintext: The string to be encrypted.
        
        @rtype:   str
        @return:  The base64 encoded plaintext.
        """
        return self.__rsa_private_encrypt_base64(plaintext)
    
    def public_encrypt(self, transport):
        """
        Encrypts the content of the transport node with public key of recipient.
        
        @type  transport: unicode
        @param transport: The <transport/> node content to be encrypted.
        
        @rtype:   tuple
        @return:  Tuple containing: (base64 encrypted transport, base64 encrypted transport-key).
        """
        
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
        """
        Decrypts a string encoded with public key of recipient.
        
        @type  encrypted: str
        @param encrypted: The base64 encrypted content of the <transport/> node.
        @type  transport_key_enc: str
        @param transport_key_enc: The base64 encrypted transport-key.
        
        @rtype:   str
        @return:  The decrypted <transport/> node content.
        """
        
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
        """
        Returns the value of the signature of a the <transport/> node. Reference is OpenSpime protocol v0.9.
        
        @type  content: str
        @param content: The string content of the <transport/> node.
        
        @rtype:   str
        @return:  The base64 encoded signature of the <transport/> node.
        """
        
        # convert to canonical XML
        content_canonical = pyopenspime.util.convert_to_canonical_xml(content)
        
        # compute sha
        s = sha.sha(content_canonical).digest()
        
        # encrypt the sha using the private RSA key
        return self.__rsa_private_encrypt_base64(s).replace('\r', '').replace('\n', '')
    
    def public_check_sign(self, content, signature):
        """
        Returns the value of the signature of a the <transport/> node. Reference is OpenSpime protocol v0.9.
        
        @type  content: str
        @param content: The string content of the <transport/> node.
        @type  signature: str
        @param signature: The signature.
        
        @rtype:   boolean
        @return:  True if signature is valid, False if it is not.
        """
        
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
    

