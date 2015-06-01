""" ####################################################################
This is the function file to help building the crypto system.
The asymmetric cryptogrphy is using PKI (Public Key Infrastructure)
for message exchange and digital signature.

In this file there are:
- Digital Signature, using ECCDSA (Elliptic Curve Digital
	Signature Algorithm)
- Shared key creation using ECDHE (Elliptoc Curve Diffie
	Hellman Ephermal)

There are three curves to use with Elliptic Curve Cryptography
- NIST P256 equivalent to AES-128 key (secp256r1)
- NIST P384 equivalent to AES-192 key (secp384r1)
- NIST P521 equivalent to AES 256 key (secp521r1)
##################################################################### """
# Using PyElliptic for Elliptic Curve Cryptography
import Crypto.Hash.SHA384 as SHA384
import pyelliptic # (pip install pyelliptic)

# curve parameter
__CURVE = 'secp521r1'



# to generate an elliptic curve key
# private key and public key pair
def generate_key():
	"""Generate a new elliptic curve keypair."""
	return pyelliptic.ECC(curve=__CURVE)

# sign a message using private key
def sign(priv, pub, msg):
	"""Sign a message with the ECDSA key."""
	return pyelliptic.ECC(curve=__CURVE, privkey=priv, pubkey=pub).sign(msg)

# verify the signature using public key
def verify(pub, msg, sig):
	"""
	Verify the public key's signature on the message. pub should
	be a serialised public key.
	"""
	return pyelliptic.ECC(curve=__CURVE, pubkey=pub).verify(sig, msg)

# create a shared key secret by using EC Diffie Hellman algorithm
# Bob Private + Alice Public == Bob Public + Alice Private
def shared_key(priv, pub):
	"""Generate a new shared encryption key from a keypair."""
	key = priv.get_ecdh_key(pub)
	key = key[:32] + SHA384.new(key[32:]).digest()
	return key