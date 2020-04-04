
import argparse
import os
import time
import socket
import sys
import binascii
from aes import AESCipher
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
'''def calC1bytes(c):

    # change long int to hex number,c1 bytes as AES key
    c1 = (c * (2 ** (b * e)) % n)
    c1bytes = long_to_bytes(c1)
    return c1bytes'''
MESSAGE_LENGTH=15
ciphertext1="""a6 b0 75 72 6c f2 bc 73  54 70 c4 94 2b c1 50 e0
  c2 5e c0 12 f4 31 a5 80  ed 3a 27 4e 89 66 e0 79 
  02 3f 2f 93 65 10 e5 b4  4b 99 2f 7b 28 dc bd 72   
  05 93 2c f6 15 a4 65 c0  07 aa 13 2b 60 9f db 13   
  8f a4 d4 37 ac 9a 0b 9c  a8 38 22 08 11 8c 24 b5   
  fb 66 75 f0 5b f9 a9 91  55 cb c5 b6 11 a4 7d b9   
  70 5e 1e 40 17 5f 42 ef  fe a3 ac 73 46 de d7 5d   
  00 85 53 98 60 6d a5 46  25 86 d5 2c 0d 9f 5c da   
  7d 37 29 19 0c c4 f0 87  ed 27 12 e7 1d 0e 50 05   
  02 ad 87 58 70 b3 61 ec  0b a7 ca e7 1c 29 6c 90   
  19 c1 8e 99 38 6d 5b ed  92 40 68 85 e2 0e ed fb   
  90 10 5f fb 91 75 25 7c  ca 26 e1 53 1b 8a 9e 7b   
  32 07 dd da 77 99 e2 13  4f 1f 1b 10 9c 54 4c cf   
  14 bb 52 7e 8b a3 28 53  29 2f 8a 8d 50 9a 30 81   
  b1 f5 d8 a8 43 da c3 5f  f6 07 32 25 f6 a5 35 bc   
  77 5c 01 d8 06 23 e2 51  22 fb c8 f1 a7 22 12 73  
  d9 93 a1 b1 b0 8a f7 34  00 bb 0e ee 37 21 a7 f8   
  05 13 23 28 8a 6e ce 06  4d aa 76 28 5c ab 4e 7d   
  16 b8 49 87 cc 04 7b b9  56 59 73 af 4b dd 0e 4d"""  


#print(ciphertext1)
#print(c)


# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress",
                    help='ip address where the server is running',
                    default='127.0.0.1',  # Defaults to loopback
                    required=True)
parser.add_argument("-p", "--port",
                    help='port where the server is listening on',
                    required=True)
parser.add_argument("-f", "--publickey",
                    help='name of public key',
                    default='serverPublicKey',
                    required=False)
parser.add_argument("-v", "--verbose",
                    help="print out extra info to stdout",
                    default='True',
                    required=False)

args = parser.parse_args()

# Create a TCP/IP socket
'''sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = (args.ipaddress, int(args.port))
sock.connect(server_address)
sock.settimeout(2)'''

#AESKey = os.urandom(32)
#while AESKey[0] == 0:  # Make sure there aren't leading 0s
    #AESKey = os.urandom(32)

#if args.verbose is True:
    #binKey = bin(int.from_bytes(AESKey, byteorder='big'))
    #print("Using AES key : {}".format(binKey))

# load server's public key
serverPublicKeyFileName = args.publickey
key = ""
with open(serverPublicKeyFileName, 'r') as f:
    key = RSA.importKey(f.read())
    n=key.n
    e=key.e
MESSAGE_LENGTH = 2048
b=255
ciphertext1 = ''.join(ciphertext1.split())
AESkey = ciphertext1[:512]
InAesK = int(AESkey,16);
'''c1 = (InAesK * (2 ** (b * e)) % n)
c1bytes = long_to_bytes(c1)
#encryptedKey = key.encrypt(c1bytes, 32)[0]
GuessAESKeybin = "0"+"".zfill(255)
if hex(int(GuessAESKeybin, 2))[-1:]=='L':
	MyguessAESKey = binascii.a2b_hex(hex(int(GuessAESKeybin, 2))[2:-1].zfill(64))
else:
	MyguessAESKey = binascii.a2b_hex(hex(int(GuessAESKeybin, 2))[2:].zfill(64))
#MyguessAESKey=
aes = AESCipher(MyguessAESKey)
msg = ""
'''
'''
try:
    # Send data
    try:
        message = aes.encrypt('THis is my test message')
    except ValueError:
        print("Client with port {} failed.".format(args.port),
              file=sys.stderr)
        exit(1)
    msg = c1bytes + message
    # msg: AES key encrypted by the public key of RSA
    #      + message encrypted by the AES key

    if args.verbose is True:
        print('Sending: {}'.format(message.hex()))
    sock.sendall(msg)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)

    if amount_expected % 16 != 0:
        amount_expected += (16 - (len(message) % 16))

    answer = b''
    if amount_expected > amount_received:
        while amount_received < amount_expected:
            try:
                data = sock.recv(MESSAGE_LENGTH)
            except socket.timeout as e:
                err = e.args[0]

                if err == 'timed out':
                    print('Connection timed out, waiting for retry',
                          file=sys.stderr)
                    time.sleep(1)
                    continue
                else:
                    print('Another issue: {}'.format(e),
                          file=sys.stderr)
                    break
            except socket.error as e:
                print('Socket error: {}'.format(e),
                      file=sys.stderr)
                break
            amount_received += len(data)
            answer += data

    print('Received: {}'.format(aes.decrypt(answer)))

finally:
    sock.close()
'''
def itWorks(b,AESKeybin):
	#connection
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(server_address)
	#parameters
	Cb=(InAesK*(2**(b*e) % n)) % n
	#print 'b = %s' % b
	if hex(int(AESKeybin, 2))[-1:]=='L':
		AESKey = binascii.a2b_hex(hex(int(AESKeybin, 2))[2:-1].zfill(64))
	else:
		AESKey = binascii.a2b_hex(hex(int(AESKeybin, 2))[2:].zfill(64))
	#decrption
	msg = ""
	msg += binascii.a2b_hex(hex(Cb)[2:-1].zfill(512))
	aes = AESCipher(AESKey)
	try:
	  message = "April"
	  msg += aes.encrypt(message)
	  sock.sendall(msg)
	  # Look for the response
	  amount_received = 0
	  amount_expected = len(message)
	  if amount_expected % 16 != 0:
		amount_expected += (16 - (len(message) % 16))
	  answer = ""
	  if amount_expected > amount_received:
		while amount_received < amount_expected:
		  data = sock.recv(MESSAGE_LENGTH)
		  amount_received += len(data)
		  answer += data
	finally:
  		sock.close()
	result=(aes.decrypt(answer) == "APRIL           ")
	if result==True:	
		print 'Cb = %s' % Cb
	return result

#initial value (verfied)
AESKeybinb255 = "1"+"".zfill(255)
AESKeybin = AESKeybinb255

for i in range(1,2):
	b=255-i
	print 'b = %s' % b
	AESKeybin0="0"+AESKeybin[:-1]
	AESKeybin1="1"+AESKeybin[:-1]
	bool0=itWorks(b,AESKeybin0)
	time.sleep(7)
	if bool0:
		AESKeybin=AESKeybin0
	else:
		bool1=itWorks(b,AESKeybin1)
		time.sleep(7)
		if bool1:
			AESKeybin=AESKeybin1
		else:
			print 'Error!'
			break
	print "AESKeybin = %s" % AESKeybin



