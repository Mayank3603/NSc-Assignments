import socket
import rsa
import json
import uuid
import pickle
import time
from datetime import datetime



class Client:
    def __init__(self, my_id, p, q):
        self.client_id = my_id
        self.public_key, self.private_key = rsa.generate_key_pair(p, q)
        print(self.public_key, self.private_key)

        self.pkda_public_key = None

    def register_with_pkda(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("localhost",50051))
            
            Request_to_register = {
                "client_id": self.client_id,
                "type_of_req": "Register",
                "public_key": list(self.public_key)
            }
            print("Sending request to register to PKDA")
            sock.sendall(json.dumps(Request_to_register).encode("utf-8"))
            response = sock.recv(8192)
            self.pkda_public_key = json.loads(response.decode())["pkda_public_key"]
            print("Received PKDA_public key ", self.pkda_public_key)
          


if __name__ == "__main__":
    client1 = Client("client_2", 31, 37)
    client1.register_with_pkda()
