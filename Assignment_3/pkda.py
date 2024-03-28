import socket
import threading
from rsa import generate_key_pair
import json
import rsa

class PKDA:
    def __init__(self, p, q):
        self.public_key, self.private_key = generate_key_pair(p, q)
        self.client_public_keys = {}
        print("Public Key:", self.public_key)
        print("Private Key:", self.private_key)
    
    def register_clients(self, client_id, pu):
        self.client_public_keys[client_id] = pu
    
    def get_client_pu(self, client_id):
        return self.client_public_keys.get(client_id)

def req_from_clients(conn, pkda):
    while True:
    
        data = conn.recv(8192)
        if not data:
            break
        print(f"Received data: {data}")
        request = json.loads(data.decode('latin-1')) 

        if request["type_of_req"] == "Register":
            public_key = list(request["public_key"])
            client_id = request["client_id"]
            pkda.register_clients(client_id, public_key)
            
            response = {"PKDA_PU": pkda.public_key}
            conn.sendall(json.dumps(response).encode())

        elif request["type_of_req"] == "Request_public_key":
            client_id = request["client_id"]
            other_client_id = request["other_client_id"]
            other_public_key = pkda.client_public_keys[other_client_id]
            if other_public_key:
                response = {
                    "pu_arg1": rsa.encrypt(pkda.private_key,str(other_public_key[0]).encode('utf-8')),
                    "pu_arg2": rsa.encrypt(pkda.private_key,str(other_public_key[1]).encode('utf-8')),
                    # "type": rsa.encrypt(request["type"].encode('utf-8'), pkda.private_key),
                    "cur_time": rsa.encrypt(pkda.private_key,request["cur_time"].encode('utf-8'))
                }
                conn.sendall(json.dumps(response).encode())
            else:
                conn.sendall(b"Public key of other client not found")

    conn.close()

if __name__ == "__main__":
    try:
        pkda = PKDA(13, 17)

        Server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        Server.bind(('localhost', 50051))
        Server.listen(10)

        print("PKDA server is listening for connections...")

        while True:
            connection, address = Server.accept()
            print(f"New connection from {address}")
            req_from_clients(connection, pkda)  

    except KeyboardInterrupt:
        print("Server stopped by keyboard interrupt")
   
