import socket
from RSA import RSA

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(), 1234))
s.listen(5)

plaintext = "This could be your super secret password or key :o"

p = RSA.P
q = RSA.Q
e = RSA.E    
key = RSA.recieve_public_key(p, q, e) # this is your public key
ciphertext = RSA.encryption(plaintext,key)
print('Plain: ',plaintext)
print('Key: ',key)
print('Cipher: ',ciphertext)
print('-----------------------------------------------')
while True:
    clientsocket, address = s.accept()
    print(f"Connection from {address} has been established.")
    clientsocket.send(bytes(ciphertext, "utf-8"))


