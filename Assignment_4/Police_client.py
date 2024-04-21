import socket
import json
import uuid
import socket
from rsa import  encrypt,decrypt
import json
import uuid
import threading
import time
from datetime import datetime
import hashlib
import random
class PoliceClient:
    def __init__(self, client_id):
        self.client_id = client_id
        with open("keys.txt", "r") as file:
            lines = file.readlines()

        self.client_public_key = tuple(int(x) for x in lines[1].strip()[1:-1].split(','))
        self.client_private_key = tuple(int(x) for x in lines[3].strip()[1:-1].split(','))
        self.server_public_key = tuple(int(x) for x in lines[5].strip()[1:-1].split(','))
        # self.server_private_key = tuple(int(x) for x in lines[7].strip()[1:-1].split(','))


        print("Client Public Key:", self.client_public_key)
        print("Client Private Key:", self.client_private_key)
        print("Server Public Key:", self.server_public_key)
        # print("Server Private Key:", self.server_private_key)

    def register_driver(self, name, driver_id, dob,fingerprint,certificate):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("localhost", 50051))

            request_to_register = {
                "type_of_req": "Register",
                "driver_data": {
                    "name": name,
                    "driver_id": driver_id,
                    "dob": dob,
                    "finger_print": fingerprint,
                    "certificate": certificate
                }
            }

            print("Sending request to register to PKDA")
            sock.sendall(json.dumps(request_to_register).encode("utf-8"))
            response = sock.recv(8192)
            print("Response from server:", response.decode("utf-8"))

    def revoke_driver(self, name, driver_id, fingerprint,certificate):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("localhost", 50051))

            request_to_revoke = {
                "type_of_req": "Revoke",
                "driver_data": {
                    "name": name,
                    "driver_id": driver_id,
                    "finger_print": fingerprint,
                    "certificate": certificate
                }
            }
            print("Sending request to revoke to PKDA")
            sock.sendall(json.dumps(request_to_revoke).encode("utf-8"))
            response = sock.recv(8192)
            print("Response from server:", response.decode("utf-8"))

    def inquire_driver(self, name, driver_id,finger_print, certificate):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("localhost", 50051))

            encoded_this = name+driver_id+finger_print+certificate

            hash_value = hashlib.sha256(encoded_this.encode()).hexdigest()
            encrypted_hash = encrypt(self.client_private_key, hash_value)

            request_to_inquire = {
                "type_of_req": "Inquire",
                "driver_data": {
                    "name": name,
                    "driver_id": driver_id,
                    "hash": encrypted_hash,
                    "time": str(time.time()),
                    "finger_print":finger_print,
                    "certificate": certificate
                }
            }

            print("Sending inquiry request to server")
            sock.sendall(json.dumps(request_to_inquire).encode("utf-8"))
            response = sock.recv(8192)
            response_data = json.loads(response.decode("utf-8"))

            driver = decrypt(self.client_private_key,response_data.get("Driver"))
            validity = decrypt(self.client_private_key,response_data.get("validity"))

            print("Driver:", driver)
            print("Validity:", validity)


if __name__ == "__main__":
    client_id = str(uuid.uuid4())  
    police_client = PoliceClient(client_id)

    while True:
        print("1. Enter a new Driver's Licence")
        print("2. Revoke a Driver's Licence")
        print("3. Check Validity")
        print("------------------")
        choice = int(input("Enter your choice: "))

        if choice == 1:
            name = input("Enter name: ")
            driver_id = input("Enter Driver's ID: ")
            dob = input("Enter Date of Birth: ")
            fingerprint = random.randint(10000, 99999)
            certificate = random.randint(1000,9999)
            police_client.register_driver(name, driver_id, dob,fingerprint, certificate)
            print("Your fingerprint is:", fingerprint)
            print("Your certificate is:", certificate)
        elif choice == 2:
            name = input("Enter name: ")
            driver_id = input("Enter Driver's ID: ")
            fingerprint = input("Enter fingerprint: ")
            certificate = input("Enter certificate: ")

            police_client.revoke_driver(name, driver_id, fingerprint, certificate)
        elif choice == 3:
            name = "Rohit"
            driver_id = "DL10-1234"
            fingerprint = "12345"
            certificate = "1234"
            police_client.inquire_driver(name, driver_id,fingerprint, certificate)

