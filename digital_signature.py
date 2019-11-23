#!/usr/bin/env python
from base64 import (
    b64encode,
    b64decode,
)
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

from __main__ import *

# When you call a script, the calling script can access the namespace of the called script. 
# This "from __main__ import *" needs to be in the calling script (AKA the one we want to use the variable in). 
# Note: The star means import anything. To avoid namespace pollution, import the variables you want individually: from __main__ import myMessage.
# The called script is the one holding the variable you want to use. In this case, it would be app.py.

# SENDER: 
# 1.) Generate A Unique Hash Of The Message.
# 2.) Encrypt The Hash Using The Senders Private Key.

# RECIPIENT: 
# 1.) Takes The Received Message & Generates Their Own Hash Of The Message.
# 2.) Decrypts The Received Encrypted Hash (The Senders Hash, Sent Along With The Message) Using The Senders Public Key.

# The recipient compares the hash they generate against the senders decrypted hash; 
# if they match, the message or digital document has not been modified and the sender is authenticated.


def sign_message(message):
	#private key is generated by the application and would be regenerated every time 
        #public key is assumed to be shared out of bound
	digest = SHA256.new()
	message_bytes= bytes(message, 'utf-8')
	# Load private key and sign message
	digest.update(message_bytes)
        # Read shared key from file
	private_key = False
	with open ("private_key.pem", "r") as myfile:
		private_key = RSA.importKey(myfile.read())
	# Load private key and sign message
	signer = PKCS1_v1_5.new(private_key)
	sig = signer.sign(digest)

	return b64encode(sig)

def verify_digital_signature(message, sig_b64):
	#this should be global and shared out of bounds
	private_key=false;
	
	digest=SHA256.new()
	digest.update(message)
	with open ("private_key.pem", "r") as myfile:
		private_key = RSA.importKey(myfile.read())
	# Load public key and verify message
	verifier = PKCS1_v1_5.new(private_key.publickey())
	verified = verifier.verify(digest, b64decode(sig_b64))	
	
	if verified:
		return "Sinature was successfully verified!"	
	else:
		return "Signature FAILED to verify"


		
