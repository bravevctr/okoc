""" #################################################################
This is the function file for my custom protocol

High-Level Handshake:
	- EXC_MESSAGE
		Client sign using ECDSA then send ECDHE parameter 
		(CLIENT_DH_PUBLIC) to server
	- EXR_MESSAGE
		Server sign using ECDSA then send ECDHE parameter
		(SERVER_DH_PUBLIC) to client along with COUNTER
	- KEY_MESSAGE
		Using generated SESSION_KEY, client encrypt signed
		COUNTER+1 and send to server
	- FIN Message
		Using generated SESSION_KEY, server encrypt signed
		'True' message and send to client. Indicating that 
		SESSION CHANNEL is successfully established

After Handshake:
	- Client/Server encrypt message using BUILD_MESSAGE
	- Client/Server decrypt message using PROCESS_MESSAGE
################################################################# """ 
import os.path 
import symmetric_tools
import asymmetric_tools

# directory parameter to store the private and public key files
__DIRECTORY = 'keys/'



def get_private_filename(mode):
	if mode == 'client': return __DIRECTORY+'client-private.key'
	elif mode == 'server': return __DIRECTORY+'server-private.key'

def get_public_filename(mode):
	if mode == 'client': return __DIRECTORY+'client-public.key'
	elif mode == 'server': return __DIRECTORY+'server-public.key'

""" NOT SECURE!!!
The protocol implementation is assuming that the client and server can
share the public keys securely without CA (Certificate Authority)
The key distibution mechanism is OUT OF SCOPE of this implementation
"""
# open required private or public keys from file
def get_private_from_file(mode):
	target = open(get_private_filename(mode), 'r')
	priv = target.read() # direct access
	target.close()
	return priv

def get_public_from_file(mode):
	target = open(get_public_filename(mode), 'r')
	pub = target.read() # direct access
	target.close()
	return pub

def write_file(filename, key):
	target = open(filename, 'w')
	target.write(key)
	target.close()

# the strippers function - LOL
def get_protocol_message(msg):
	return msg[:3]
def get_counter(msg):
	return msg[3:4] # 1 byte counter
def get_received_pub(msg, sig_len):
	return msg[int(sig_len):]
def get_received_sign(msg, sig_len):
	return msg[:int(sig_len)]
def get_encrypted_data(msg):
	return msg[3:]

def generate_ECDSA_private_public_pair(mode):
	# generate ECDSA private/public key pairs
	# check wheter private key and public key is exist
	# create new one if not exist
	if os.path.isfile(get_private_filename(mode)) and \
		os.path.isfile(get_public_filename(mode)):
		# do nothing
		print "*** Digital Private/Public Key Pair exist"
	else:
		key = asymmetric_tools.generate_key() # generate ECC keys
		write_file(get_private_filename(mode), key.get_privkey())
		write_file(get_public_filename(mode), key.get_pubkey())
		print "*** Digital Private/Public Key Pair is generated"

# generate ECDHE priv and pub pair
def generate_ECDHE_parameter():
	pre_session_key = asymmetric_tools.generate_key() # ECC keys pair
	dh_priv = pre_session_key.get_privkey()
	dh_pub = pre_session_key.get_pubkey()
	return pre_session_key, dh_priv, dh_pub

# to build signature
def build_signature(mode, msg):
	sig = asymmetric_tools.sign(get_private_from_file(mode), \
			get_public_from_file(mode), msg)
	sig_len = len(sig)
	return sig, sig_len

# mode is to get public key from the opposite side
def check_signature(mode, msg, sig):
	# verify sign,
	# the progrm will exit eventually if the signature is invalid
	is_signed = asymmetric_tools.verify(get_public_from_file(mode), \
					msg, sig)
	# break the protocol when signature is invalid
	if is_signed == True:
		print "*** Signature is verified"
	elif is_signed == False:
		print "Invalid Signature"
		exit()

# create shared session key
def create_session_key(mode, data_splited, sig_len, pre_session_key):
	# get signature and public key
	sig = get_received_sign(data_splited, sig_len)
	dh_pub = get_received_pub(data_splited, sig_len)
	print "*** DH Public is received"

	# verify sign
	check_signature(mode, dh_pub, sig)

	# generate session key
	session_key = asymmetric_tools.shared_key(pre_session_key, dh_pub)
	print ""
	print "*** Session Key:"
	print session_key
	
	return session_key



""" BUILD FUNCTIONS - Custom Protocol """
def BUILD_EXC_MESSAGE(mode, dh_pub):
	PROTO_MSG = 'EXC'
	# sign the ECDHE public
	client_sig = build_signature(mode, dh_pub)
	# craft message protocol msg and public key
	return PROTO_MSG+str(client_sig[1])+'\x80'+client_sig[0]+dh_pub

def BUILD_EXR_MESSAGE(mode, dh_pub, last_counter):
	PROTO_MSG = 'EXR'
	# sign the ECDHE public
	server_sig = build_signature(mode, dh_pub)
	# send protocol msg, counter and public key
	return PROTO_MSG+str(last_counter)+str(server_sig[1]) \
				+'\x80'+server_sig[0]+dh_pub

def BUILD_KEY_MESSAGE(mode, data, session_key):
	PROTO_MSG = 'KEY'
	# send back response as 'KEY' message
	counter = int(get_counter(data)) + 1
	client_sig = build_signature(mode, str(counter))
	to_encrypt = str(client_sig[1])+'\x80'+client_sig[0]+str(counter)
	# protocol msg is not encrypt. only counter is ecnrypted
	return PROTO_MSG+symmetric_tools.encrypt(to_encrypt, session_key)

def BUILD_FIN_MESSAGE(mode, data, session_key):
	PROTO_MSG = 'FIN'
	# send back response as 'FIN' message
	server_sig = build_signature(mode, data)
	to_encrypt = str(server_sig[1])+'\x80'+server_sig[0]+data
	# protocol msg is not encrypt. only data is ecnrypted
	return PROTO_MSG+symmetric_tools.encrypt(to_encrypt, session_key)

# sign and encrypt normal messages
def BUILD_MESSAGE(mode, data, session_key):
	sig = build_signature(mode, data)
	to_encrypt = str(sig[1])+'\x80'+sig[0]+data
	return symmetric_tools.encrypt(to_encrypt, session_key)



""" PROCESS FUNCTIONS - Custom Protocol"""
def PROCESS_EXC_MESSAGE(data, pre_session_key):
	print "*** Receive EXC Message"
	
	data_splited = data.split('\x80', 1)
	sig_len = data_splited[0]
	sig_len = sig_len[3:]
	
	session_key = create_session_key('client', data_splited[1], sig_len, pre_session_key)
	return session_key

def PROCESS_EXR_MESSAGE(data, pre_session_key):
	print "*** Receive EXR Message"

	data_splited = data.split('\x80', 1)
	sig_len = data_splited[0]
	sig_len = sig_len[4:] # remember 1 byte counter
	
	session_key = create_session_key('server', data_splited[1], sig_len, pre_session_key)
	return session_key

def PROCESS_KEY_MESSAGE(data, session_key, last_counter):
	print "*** Receive KEY Message"
	recv_key = symmetric_tools.decrypt(get_encrypted_data(data), session_key)

	data_splited = recv_key[0].split('\x80', 1)
	sig_len = data_splited[0]

	sig = get_received_sign(data_splited[1], sig_len)
	msg = get_received_pub(data_splited[1], sig_len)
	# verify sign
	check_signature('client', msg, sig)

	# verify that the counter is correct
	if int(msg) == last_counter + 1:
		print "*** OK client have the same key with server"
		return True

def PROCESS_FIN_MESSAGE(data, session_key):
	print "*** Receive FIN Message"
	recv_fin = symmetric_tools.decrypt(get_encrypted_data(data), session_key)

	data_splited = recv_fin[0].split('\x80', 1)
	sig_len = data_splited[0]

	sig = get_received_sign(data_splited[1], sig_len)
	msg = get_received_pub(data_splited[1], sig_len)
	# verify sign
	check_signature('server', msg, sig)

	# verify that the msg is 'True'
	if str(msg) == 'True':
		print "*** SECURE CHANNEL IS ESTABLISHED #########"
		return True

# decrypt and verify normal messages
# mode must be opposite side
def PROCESS_MESSAGE(mode, data, session_key):
	recv_msg = symmetric_tools.decrypt(data, session_key)

	data_splited = recv_msg[0].split('\x80', 1)
	sig_len = data_splited[0]

	sig = get_received_sign(data_splited[1], sig_len)
	msg = get_received_pub(data_splited[1], sig_len)
	# verify sign
	check_signature(mode, msg, sig)

	return msg