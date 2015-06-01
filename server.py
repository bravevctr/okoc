import socket
import protocol

print "*** Cryptography Class Programming Assignment"
print "*** by Yustus Eko Oktian / 20145039"
print "*** server.py"
print ""

# connection parameter
TCP_IP = '127.0.0.1' # server IP
TCP_PORT = 5005 # server port
BUFFER_SIZE = 1024  # Normally 1024, but we want fast response

# open socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)

print "*** Waiting TCP Connection from Client ..."
conn, addr = s.accept()
print 'Client connected:', addr
print ""

# ensure ECDSA priv and pub is generated or exist
protocol.generate_ECDSA_private_public_pair('server')
KEY_PAIRS = ''
SESSION_KEY = ''
LAST_COUNTER = 0 # 1 byte counter

while 1:
	data = conn.recv(BUFFER_SIZE)
	if not data: break
	
	if protocol.get_protocol_message(data) == "EXC":
		KEY_PAIRS = protocol.generate_ECDHE_parameter()
		session_key = protocol.PROCESS_EXC_MESSAGE(data, KEY_PAIRS[0])
		
		""" Send EXR MEssage """
		to_send = protocol.BUILD_EXR_MESSAGE('server', KEY_PAIRS[2], LAST_COUNTER)
		conn.send(to_send)

	elif protocol.get_protocol_message(data) == "KEY":
		is_same_key_generated = protocol.PROCESS_KEY_MESSAGE(data, \
									session_key, LAST_COUNTER)
		if is_same_key_generated == True:
			LAST_COUNTER = LAST_COUNTER + 1
			if LAST_COUNTER >= 9: LAST_COUNTER = 0 # reset to 0 beacuse only 1 byte

			""" Send FIN Message """
			to_send = protocol.BUILD_FIN_MESSAGE('server', 'True', session_key)
			conn.send(to_send)
		
	else:
		""" Send DATA """
		# normal TCP request/reply
		print ""
		decrypted_data = protocol.PROCESS_MESSAGE('client', data, session_key)
		print "Received ChiperText:", data
		print "Received PlainText:", decrypted_data

		# reply as ACK
		to_send = protocol.BUILD_MESSAGE('server', 'Message Received!', session_key)
		conn.send(to_send)

conn.close()