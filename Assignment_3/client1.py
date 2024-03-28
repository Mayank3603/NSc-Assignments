import socket
import rsa
import json
import uuid
import pickle
import threading
import time
from datetime import datetime



class Client:
    def __init__(self, my_id, p, q):
        self.client_id = my_id
        self.public_key, self.private_key = rsa.generate_key_pair(p, q)
        print(self.public_key, self.private_key)

        self.pkda_public_key = None

    def register_at_pkda(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
            socket.connect(("localhost",50051))
            
            Request_to_register = {
                "client_id": self.client_id,
                "type_of_req": "Register",
                "public_key": list(self.public_key)
            }
            print("Sending request to register to PKDA")
            socket.sendall(json.dumps(Request_to_register).encode("utf-8"))
            response = socket.recv(8192)
            self.pkda_public_key = json.loads(response.decode())["PKDA_PU"]
            print("Received PKDA_public key ")
            print(self.pkda_public_key)
    def req_pu_other(self, other_client_id):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
            socket.connect(("localhost",50051))
            print(f"Sending request to get public key of {other_client_id} to PKDA")
            Request_PU_of_PKDA = {
                "type_of_req": "Request_public_key",
                "client_id": self.client_id,
                "other_client_id": other_client_id,
                "cur_time": datetime.now().strftime("%H:%M:%S")
            }
            socket.sendall(json.dumps(Request_PU_of_PKDA).encode("utf-8"))

            response = json.loads(socket.recv(8192).decode("utf-8"))
            print(f"Received public key from PKDA: {response}")
            target_public_key = (int(rsa.decrypt(response["pu_arg1"], self.pkda_public_key).decode('utf-8')), int(rsa.decrypt(response["target_public_key_B"], self.pkda_public_key).decode('utf-8')))
            time = rsa.decrypt(response["time"], self.pkda_public_key).decode('utf-8')
            # target_public_key = tuple(response["target_public_key"])
            print(f"{self.client_id} Got public key of {target_client_id} at Time: {time}")
            return target_public_key


if __name__ == "__main__":
    client1 = Client("client_1", 23, 29)
    client1.register_at_pkda()
    client1.req_pu_other("client_2")
