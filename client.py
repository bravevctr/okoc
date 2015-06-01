import socket
import protocol

print "*** Cryptography Class Programming Assignment"
print "*** by Yustus Eko Oktian / 20145039"
print "*** client.py"
print ""

# connection parameter
TCP_IP = '127.0.0.1' # server IP
TCP_PORT = 5005 # server port
BUFFER_SIZE = 1024 # buffer size

print "*** Connecting to server ..."
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	s.connect((TCP_IP, TCP_PORT))
	print "*** Connected to %s at port %d" % (TCP_IP, TCP_PORT)
	print ""
except Exception, e:
	print('something\'s wrong with %s:%d. Exception type is %s' \
	% (TCP_IP, TCP_PORT, `e`))
	exit()

# ensure ECDSA priv and pub is generated or exist
protocol.generate_ECDSA_private_public_pair('client')
KEY_PAIRS = '' 
SESSION_KEY = ''

# initiate handshake
""" Send EXC Message """
KEY_PAIRS = protocol.generate_ECDHE_parameter()
to_send = protocol.BUILD_EXC_MESSAGE('client', KEY_PAIRS[2])
s.send(to_send)

while 1:
	data = s.recv(BUFFER_SIZE)
	if not data: break

	if protocol.get_protocol_message(data) == 'EXR':
		SESSION_KEY = protocol.PROCESS_EXR_MESSAGE(data, KEY_PAIRS[0])

		""" Send KEY Message """
		# build 'KEY' message for final handshake
		to_send = protocol.BUILD_KEY_MESSAGE('client', data, SESSION_KEY)
		s.send(to_send)

	elif protocol.get_protocol_message(data) == 'FIN':
		is_session_created = protocol.PROCESS_FIN_MESSAGE(data, SESSION_KEY)
		if is_session_created is not True:
			print "*** SECURE CHANNEL CAN'T BE ESTABLISHED ##########"
			exit()
		elif is_session_created is True:
			print ""
			print "*** Please insert messaages to be encrypted"
			print "*** Type exit() to exit"
			print ""

			# get user input
			message = raw_input("Messsages: ")
			if message == "exit()": exit()
			# build ciphertext and send
			chp = protocol.BUILD_MESSAGE('client', message, SESSION_KEY)
			print "ChiperText:", chp
			s.send(chp)
			
	else:
		""" Send DATA """
		# get reply from server (ACK)
		print protocol.PROCESS_MESSAGE('server', data, SESSION_KEY)

		print ""
		# get user input
		message = raw_input("Messsages: ")
		if message == "exit()": exit()
		# build ciphertext and send
		chp = protocol.BUILD_MESSAGE('client', message, SESSION_KEY)
		print "ChiperText:", chp
		s.send(chp)
		
s.close()