from Crypto.Cipher import AES
import socket

def do_encrypt(message):
    obj = AES.new('This is a key123'.encode("utf8"), AES.MODE_CFB, 'This is an IV456'.encode("utf8"))

    ciphertext = obj.encrypt(message)
    return ciphertext
    """  length = 16 - (len(obj) % 16)
    obj += bytes([length])*length   """



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(), 1234))
s.listen(5)

ciphertext = do_encrypt("This could be your super secret password :o".encode("utf8"))

while True:
    clientsocket, address = s.accept()
    print(f"Connection from {address} has been established.")
    clientsocket.send(bytes(ciphertext))


