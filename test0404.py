import argparse
import os
import time
import socket
import sys
import binascii
from aes import AESCipher
#from Crypto.PublicKey import RSA
#from Crypto.Util.number import *
AESKeybin = "0101001100111000000101000000001101100010000011000100011010010110010101000000100111111101010011110111000101010011100110001101001000110101011010101111001000110100100011011111010001011001001110100011111010110111100010101000110000010101101001001110100010110010"
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
ciphertext1 = ''.join(ciphertext1.split())
message = ciphertext1[512:]

c = int(message,16);
encryptedMessage = long_to_bytes(c)

#aes = AESCipher(MyguessAESKey)
AESKeyInt2 = int(AESKeybin, 2)
AESKey2 = long_to_bytes(AESKeyInt2)
aes2 = AESCipher(AESKey2)
#print(FinalAES)
#print(AESKeyInt2)
print(AESKey2)
#print(aes2)
#print(len(FinalAES))
#serverInt = int(servertext[:256],16)
#serverBytes = long_to_bytes(serverInt)
#print(serverBytes)
#print aes2.decrypt(servertext[:256])
print (aes2.decrypt(encryptedMessage))
