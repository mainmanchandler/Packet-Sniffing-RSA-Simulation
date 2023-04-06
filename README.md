## Packet-Sniffing-RSA-Simulation
 Small python socket to simulate the effects of using RSA when transferring unprotected and RSA encrypted text data over a local network

# How to use:
1. Download wireshark to look at local network packets
2. run the server.py
3. run the client.py
4. look at the packets being sent
5. repeat steps 1-4 for secure & unsecure server-clients to see effect

├── Not Secure
│   ├── client.py       <- mock client socket used for packet transfer across local network
│   ├── server.py       <- mock server socket used for packet transfer across local network
│
├── SecureImplementation
│   ├── client.py       <- mock client socket used for packet transfer across local network
│   ├── server.py       <- mock server socket used for packet transfer across local network
│   ├── RSA.py          <- RSA implementation from scratch, containing methods of encryption, 
|                        decyption, recieve_public_key, and recieve_private_key keys. 
