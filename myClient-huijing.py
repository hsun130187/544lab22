
# coding: utf-8

# In[1]:

import argparse
import os
import time
import socket
import sys
from aes import AESCipher
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
import binascii


# In[2]:

#ciphertext='a72b7ef9a53aa186298489bb82082e30ee21773b3d6eae3cd675d8974295204ff88eb2c439fab91401b1eab23f8408f063f63f0a9a239d4d76134e820d08b90a8de2248db815e87c043dbdad4b957e4646271a8fd2e8664b20920a5121ae454d0b7de6f027a06ed6c5b9e7b94a19bc472a5e3a736ba8e20e0e8e6144121bd394c81e90ee99157ff428f84a2bf7d88967952ba965306610e47e1b98f9ba987be904628d2cfa2722403c2756af488bc1e7c3704a97009c1cd5a5b475db11268bfd6943de1b92325bf9d7a62119ac0d5a1e1915e9016c0cb84459b91b3046379ffed6017e9bccf3fc493f1e7334c220248973cfa61238e8f10eccb3569f99cddb8db7c7c133531af0bd8ce24138cf2c969b'


# In[3]:

#pcap3
ciphertext='98cd0323ed99e1ad142637e808b00efc66e7a1b87d722dd5c9d20de6622053ddb7240550bd77b901a167f3953e9b1858c84daedf01a7fc2a36130a2f1a0bfa7d6a7508d15c9bd139c6a94390051cf0634a8697e78ea7738a6b3102da448d7193bd65757c7f3f70e2ac82a8c2cac9be7f6b6a8b8386e4f96e4c12f714e40832364d5793387d3d44e75b61c8bd788e8e94e9cc460db79f16c574acf5e7170ce5887f2f96bc1fa40c59824f18c825a70b4ee14f662531a981a84da99ef68ecba3c088485a4d8916312b9b32dbdf07ddd3a5d76ed1c74593ebbaec9ec3abd8616d13958fd845990765955a3d25c38190b44da6eec37c37cdab8a74495bfa53ffb1fa6b16007e3b6d2be1f70e8232498453e1'


# In[4]:

# ciphertext='1379f9fa241727e2b8a1b967193887570599d0cbdb4cc664\
# 31f0c038c62e71f1bebbfc7a8bfec484ea872b4c46aa895f1f71c4f529829\
# c6e31fce0a3610d82c903ed7f04647e7057d39a0204a818b70a11ec189ff7\
# 37b78342f28bd30a490090c2c5f195b5267e7dc1fcf5c3867771c2d17c008c\
# 4e3a6e754ae58208c0f53a2d03d6d1164c944357b66c7d5ebfd257c7757870b\
# 801fca667517a05b171414f5c616317a1148c52ae3abe5afdad2099b56356fe3\
# 721e6dc5681f351228f14f83e947e2a4d8c71196fa7cbd4498f911ef63bd7a0c\
# 5da183273a28c4e0144694f7c42900f083f3f56d55e9029b3b623f443fbd7057d\
# f6d5cf79efd317b65813bf748610456094a7ba1db8313631ae9697d0'


# In[5]:

# load server's public key
serverPublicKeyFileName = "serverPublicKey"
key = ""
with open(serverPublicKeyFileName, 'r') as f:
    key = RSA.importKey(f.read())

n=key.n
e=key.e


# In[6]:

AESkey=ciphertext[:512]
c = int(AESkey,16)
#print(len(str(c)))
b=255
#cipherc=(c*(2**(b*e))%n)%n
cipherc=(c * (2 ** (b * e)) % n)
ciphercbyte= long_to_bytes(cipherc)


# In[7]:

MESSAGE_LENGTH = 2048
guessAESkey = '1'+'0'*b


# In[8]:

myguesskey=long_to_bytes(int(guessAESkey,2))
#print(len(myguesskey))
# if AESkey less then 32 hex, add hex b'\x00' * less bytes numbers
if len(myguesskey) < 32:
    #print('myguesskey length<32')
    myguesskey = myguesskey + b'\x00' * (32 - len(myguesskey) % 32)
#print('myguesskey length', len(myguesskey))


# In[9]:

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('127.0.0.1', 10047)
sock.connect(server_address)
sock.settimeout(2)


# In[10]:

msg=''
#msg=bytes()
#msg += ciphercbyte
#msg += binascii.a2b_hex(hex(cipherc)[2:-1].zfill(512))
aes=AESCipher(myguesskey)


# In[11]:

try:
    # Send data
    try:
        message = 'test'
        msg = ciphercbyte + aes.encrypt(message)
        #print(type(msg))
    except ValueError:
        print("Client with port {} failed.".format(10047),
              file=sys.stderr)
        exit(1)
    
    # msg: AES key encrypted by the public key of RSA
    #      + message encrypted by the AES key

    #if args.verbose is True:
       # print('Sending: {}'.format(message.hex()))
    
    sock.sendall(msg)
    # Look for the response
    amount_received = 0
    amount_expected = len(message)

    if amount_expected % 16 != 0:
        amount_expected += (16 - (len(message) % 16))

    answer = bytes()
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
            #print(answer)

    print('Received: {}'.format(aes.decrypt(answer)))
finally:
    sock.close()






