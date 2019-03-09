import socket
import sys

HOST ='127.0.0.1'
PORT ='555'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(HOST,PORT)
s.close()
print("packet transfer done")
