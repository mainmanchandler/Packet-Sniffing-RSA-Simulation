from Crypto.Cipher import AES
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 1234))

def do_decrypt(ciphertext):
    obj2 = AES.new('This is a key123'.encode("utf8"), AES.MODE_CFB, 'This is an IV456'.encode("utf8"))
    message = obj2.decrypt(ciphertext)
    return message

message = s.recv(1024)

message_decoded = do_decrypt(message)

print(message_decoded)