import socket
from RSA import RSA

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 1234))


ciphertext_encoded = s.recv(1024)
#print(ciphertext)
cipher_text = ciphertext_encoded.decode('utf-8')
#ciphertext = str(ciphertext)

p = RSA.P
q = RSA.Q
e = RSA.E 

private_key = RSA.recieve_private_key(p, q, e)
print("Cipher: ", cipher_text)
back_to_plaintext = RSA.decryption(cipher_text, private_key)
print("Decrypted Text: ", back_to_plaintext)