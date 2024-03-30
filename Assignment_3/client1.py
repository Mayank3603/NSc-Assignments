import socket
import rsa
import json
import uuid
import threading
import time
from datetime import datetime

class Client:
    def __init__(self, my_id, p, q):
        self.client_id = my_id
        self.public_key, self.private_key = rsa.generate_key_pair(p, q)
        # print(self.public_key, self.private_key)

        self.pkda_public_key = None
        self.other_client_publickey=None

    def register_at_pkda(self):
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
            self.pkda_public_key = json.loads(response.decode())["PKDA_PU"]
            print("Received PKDA_public key and client has been register")
            print(self.pkda_public_key)
    def req_pu_other(self, other_client_id):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("localhost",50051))
            print(f"Sending request to get public key of {other_client_id} to PKDA")
            Request_PU_of_PKDA = {
                "type_of_req": "Request_public_key",
                "client_id": self.client_id,
                "other_client_id": other_client_id,
                "cur_time": datetime.now().strftime("%H:%M:%S")
            }
            sock.sendall(json.dumps(Request_PU_of_PKDA).encode("utf-8"))

            response = json.loads(sock.recv(8192).decode())
            print(f"Received public key from PKDA: {response}")
            print()
            other_public_key = (int(rsa.decrypt(self.pkda_public_key,response["pu_arg1"])), int(rsa.decrypt(self.pkda_public_key,response["pu_arg2"])))
            time = rsa.decrypt(self.pkda_public_key,response["cur_time"])
            
            print(f"{self.client_id} Got public key of {other_public_key} at Time: {time}")
            self.other_client_publickey=other_public_key

    def generate_nonce(self):
        return uuid.uuid4().hex 
    
    def send_handshake(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("localhost",50053))
            Request = {
                "type_of_req":rsa.encrypt(self.other_client_publickey,"Request_handshake"),
                "client_id":rsa.encrypt(self.other_client_publickey,self.client_id),
                "Nonce": rsa.encrypt(self.other_client_publickey,str(self.generate_nonce()))
            }
            print("Sending hankshape request")
            sock.sendall(json.dumps(Request).encode())
            response = json.loads(sock.recv(8192).decode())
            print(f"Received reply to handshake request from client2: {response}")
            type_of_req=rsa.decrypt(self.private_key,response["type_of_req"])
            # print(type_of_req)
            if(type_of_req=="Reply to handshake request"):
                print(f"Sending confirmation of handshake to client_2")
                Nonce2=rsa.decrypt(self.private_key,response["Nonce_2"])
                response={
                    "type_of_req": rsa.encrypt(self.other_client_publickey,"Confirmation handshake"),
                    "Nonce_2": rsa.encrypt(self.other_client_publickey,Nonce2)
                }
                sock.sendall(json.dumps(response).encode())
        

    def send_hi_messages(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("localhost", 50053))  # Connect to client2
            print()
            for i in range(1, 4):
                hi_message = f"Hi_{i}"
                print(f"Sending Hi message: {hi_message}")
                request = {
                    "type_of_req": rsa.encrypt(self.other_client_publickey, "Hi_message"),
                    "Hi_message": rsa.encrypt(self.other_client_publickey, hi_message)
                }
                sock.sendall(json.dumps(request).encode())
                time.sleep(1)  
                response = json.loads(sock.recv(8192).decode())
                got_mssg=rsa.decrypt(self.private_key,response["got_mssg"])
                print(f"Received {got_mssg} message from client_2")

if __name__ == "__main__":
    client1 = Client("client_1", 23, 29)
    client1.register_at_pkda()
    client1.req_pu_other("client_2")
    client1.send_handshake()
    client1.send_hi_messages()
