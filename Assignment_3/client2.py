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
        self.flag=0

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
            print("Received PKDA_public key ")
            # print(self.pkda_public_key)
            
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
            print(f"Received public key from PKDA: client 1")
            other_public_key = (int(rsa.decrypt(self.pkda_public_key,response["pu_arg1"])), int(rsa.decrypt(self.pkda_public_key,response["pu_arg2"])))
            time = rsa.decrypt(self.pkda_public_key,response["cur_time"])
            
            print(f"{self.client_id} Got public key of {other_public_key} at Time: {time}")
            self.other_client_publickey=other_public_key
            # print(self.other_client_publickey)
            
    def generate_nonce(self):
        # print(uuid.uuid4().hex )
        return uuid.uuid4().hex 
    
    def handle_req(self, connection):
        while True:
    
            data = connection.recv(8192)
                
            if not data:
                break
            # print(f"Received data from client 1: {data}")
            request = json.loads(data.decode('latin-1')) 
            # request=json.loads(data.decode()) 
            # request = json.loads(connection.recv(8192).decode())
            # print(request)
            # other_public_key = (int(rsa.decrypt(self.pkda_public_key,response["pu_arg1"])), int(rsa.decrypt(self.pkda_public_key,response["pu_arg2"])))
            # time = rsa.decrypt(self.pkda_public_key,response["cur_time"])
            if(self.flag==0):
                self.req_pu_other("client_1")  
                self.flag=1 
            type_of_req=rsa.decrypt(self.private_key,request["type_of_req"])
            # print(type_of_req)
            if(type_of_req=="Request_handshake"):

                print("Received handshake request from client_1")
                client_id=rsa.decrypt(self.private_key,request["client_id"])
                Nonce_1=rsa.decrypt(self.private_key,request["Nonce"])
            #  "client_id":rsa.encrypt(self.other_client_publickey,self.client_id),
            #     "Nonce": rsa.encrypt(self.other_client_publickey,str(self.generate_nonce()))
                if client_id:
                    response={
                        "type_of_req":rsa.encrypt(self.other_client_publickey,"Reply to handshake request"),
                        "client_id" : rsa.encrypt(self.other_client_publickey,self.client_id),
                        "Nonce_1" : rsa.encrypt(self.other_client_publickey,Nonce_1),
                        "Nonce_2" : rsa.encrypt(self.other_client_publickey,self.generate_nonce())

                    }
                    print("Sending reply to handshake request")
                    connection.sendall(json.dumps(response).encode())

                else :
                    print("No Handshake request received")
            elif(type_of_req=="Confirmation handshake"):
                print("Received Confirmation from client_1")
            
            elif type_of_req == "Hi_message":
                hi_mssg = rsa.decrypt(self.private_key, request["Hi_message"])
                print(f"Received message: {hi_mssg}")
                got_mssg = f"Got_{hi_mssg[-1]}"
                response = {
                    "type_of_req": rsa.encrypt(self.other_client_publickey, "Got Message"),
                    "got_mssg": rsa.encrypt(self.other_client_publickey, got_mssg)
                }
                print("Sending response to Hi message")
                connection.sendall(json.dumps(response).encode())

    def receive_handshake(self):
        
        Server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        Server.bind(('localhost', 50053))
        Server.listen(15)

        print("Waiting for client1 to send handshake request")

        while True:
            connection, address = Server.accept()
            print(f"Received handshake connection from {address}")
            self.handle_req(connection)


if __name__ == "__main__":
    client2 = Client("client_2", 31, 37)
    client2.register_at_pkda()
    client2.receive_handshake()
