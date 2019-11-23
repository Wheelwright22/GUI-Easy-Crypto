from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
import os
import base64
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from __main__ import *

# When you call a script, the calling script can access the namespace of the called script. 
# This "from __main__ import *" needs to be in the calling script (AKA the one we want to use the variable in). 
# Note: The star means import anything. To avoid namespace pollution, import the variables you want individually: from __main__ import myMessage.
# The called script is the one holding the variable you want to use. In this case, it would be app.py.

def generateSymmetricKey(encryption_password):
	# We Are Asking A User For A Password. We Will Use It As A Seed.
	# We Then Generate a Key From The Password. The key From The Pass Is Just A Salted Hash.

	encpass = encryption_password.encode('utf-8')

	# Random Generated 128-Bit Salt
	salt = os.urandom(16)	#Length 16 Is In Bytes. 8 Bits In A Byte = 128-bits. Must Be Of Type Bytes.

	# derive
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend()) #Length 32 is in bytes. 8 bits in a byte = 256-bits
	
	# The variable key will now have the value of a url safe base64 encoded key.
	key = base64.urlsafe_b64encode(kdf.derive(encpass))
	
	#This key will have a type of bytes, so if you want a string you can call key.decode() to convert from UTF-8 to Pythons string type.
	
	return(key)

def symmetricEncrypt(message, associated_data):
    
    key = generateSymmetricKey(encryption_password)
    
    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a randomly generated IV.
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()

    # associated_data will be authenticated but not encrypted, it must also be passed in on decryption.
    # encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext message and get the associated ciphertext. GCM does not require padding.
    ciphertext = encryptor.update(messsage) + encryptor.finalize()

    return (iv, ciphertext)
    
    
def symmetricDecrypt(key, associated_data, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the GCM tag used for authenticating the message.
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()

    # We put associated_data back in or the tag will fail to verify when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext. If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()
