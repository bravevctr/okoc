""" #################################################################
This is the function file to help building the crypto system.
The symmetric cryptography is using AES in CBC mode

Couples things to be mentioned:
- dont use python standard random function. is not secure
- dont use == (equal) operator of python. is also not secure
################################################################# """ 
# using PyCrypto library (pip install pycrypto)
import Crypto.Random.OSRNG.posix as RNG
import Crypto.Cipher.AES as AES
import Crypto.Hash.HMAC as HMAC
import Crypto.Hash.SHA384 as SHA384
import streql # (pip install streql)

# key and tag parameters
""" From a single long key, we split into two: 
one for encryption, one for tag """
__AES_KEYLEN = 32
__TAG_KEYLEN = 48
__TAG_LEN = __TAG_KEYLEN
KEYSIZE = __AES_KEYLEN + __TAG_KEYLEN



# padding to 16 bytes for AES
def pad_data(data):
	"""pad_data pads out the data to an AES block length."""
	# return data if no padding is required
	if len(data) % 16 == 0: 
		return data

	# subtract one byte that should be the 0x80
	# if 0 bytes of padding are required, it means only
	# a single \x80 is required.

	padding_required = 15 - (len(data) % 16)
	data = '%s\x80' % data
	data = '%s%s' % (data, '\x00' * padding_required)
	return data

# unpadding the 16 bytes AES
def unpad_data(data):
	"""unpad_data removes padding from the data."""
	if not data: 
		return data

	# rstrip function is to strip all the '\x00' from the tail of the string
	data = data.rstrip('\x00')
	if data[-1] == '\x80':
		return data[:-1]
	else:
		return data

# to generate random nonce using RNG
# do not use python random function for crytopgraphy
def generate_nonce():
	"""Generate a random number used once."""
	return RNG.new().read(AES.block_size)

# generate a tag for hashing algorithm HMAC
def new_tag(ciphertext, key):
	"""Compute a new message tag using HMAC-SHA-384."""
	return HMAC.new(key, msg=ciphertext, digestmod=SHA384).digest()

# the python == (equal) operator is vulnerable to timing attacks
# therefore use streql library (pip install streql)
# to validate tag from the ciphertext
def verify_tag(ciphertext, key):
	"""Verify the tag on a ciphertext."""
	tag_start = len(ciphertext) - __TAG_LEN
	data = ciphertext[:tag_start]
	tag = ciphertext[tag_start:]
	actual_tag = new_tag(data, key)
	return streql.equals(actual_tag, tag)

# encrypt using symmetric AES
def encrypt(data, key):
	"""
	Encrypt data using AES in CBC mode. The IV is prepended to the
	ciphertext.
	"""
	# first, pad the data fixed to the block cipher size
	data = pad_data(data)
	# generate random nonce for IV
	ivec = generate_nonce()
	# encrypt
	aes = AES.new(key[:__AES_KEYLEN], AES.MODE_CBC, ivec)
	ctxt = aes.encrypt(data)
	# generate tag
	tag = new_tag(ivec + ctxt, key[__AES_KEYLEN:]) 
	return ivec + ctxt + tag

# decrypt using symmetric AES
# based on Boneh lecture, we must not notify error whether it is
# because of invalid ciphertext or invalid tag
# therefore use the same return None, False
def decrypt(ciphertext, key):
	"""
	Decrypt a ciphertext encrypted with AES in CBC mode; assumes the IV
	has been prepended to the ciphertext.
	"""
	# check if block is invalid, return False
	if len(ciphertext) <= AES.block_size:
		return None, False
	# strip down IV, ciphertext and tag
	tag_start = len(ciphertext) - __TAG_LEN # the last is tag
	ivec = ciphertext[:AES.block_size] # the first block is IV
	data = ciphertext[AES.block_size:tag_start] # the rest is ciphertext
	# first. verify the tag
	if not verify_tag(ciphertext, key[__AES_KEYLEN:]):
		return None, False
	# decrypt
	aes = AES.new(key[:__AES_KEYLEN], AES.MODE_CBC, ivec)
	data = aes.decrypt(data)
	return unpad_data(data), True