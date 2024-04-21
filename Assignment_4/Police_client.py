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
import assign_key
# from assign_key import get_client_public_key, get_client_private_key, get_server_public_key, get_server_private_key


class PoliceClient:
    def __init__(self, client_id):
        self.client_id = client_id
        with open("keys.txt", "r") as file:
            lines = file.readlines()

            # # Assign specific lines to keys
            self.client_public_key = tuple(map(int, lines[1][1:-2].split(',')))
            self.client_private_key = tuple(map(int, lines[3][1:-2].split(',')))
            self.server_public_key = tuple(map(int, lines[5][1:-2].split(',')))
            self.server_private_key = tuple(map(int, lines[7][1:-2].split(',')))

            # self.client_public_key =(73, 221)
            # self.client_private_key = (121, 221)
            # self.server_public_key = (91, 437)
            # self.server_private_key = (235, 43)

        print("Client Public Key:", self.client_public_key)
        print("Client Private Key:", self.client_private_key)
        print("Server Public Key:", self.server_public_key)
        print("Server Private Key:", self.server_private_key)

    def register_driver(self, name, driver_id, dob):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("localhost", 50051))

            request_to_register = {
                "type_of_req": "Register",
                "driver_data": {
                    "name": name,
                    "driver_id": driver_id,
                    "dob": dob
                }
            }
            print("Sending request to register to PKDA")
            sock.sendall(json.dumps(request_to_register).encode("utf-8"))
            response = sock.recv(8192)
            print("Response from server:", response.decode("utf-8"))

    def revoke_driver(self, name, driver_id):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("localhost", 50051))

            request_to_revoke = {
                "type_of_req": "Revoke",
                "driver_data": {
                    "name": name,
                    "driver_id": driver_id
                }
            }
            print("Sending request to revoke to PKDA")
            sock.sendall(json.dumps(request_to_revoke).encode("utf-8"))
            response = sock.recv(8192)
            print("Response from server:", response.decode("utf-8"))

    def inquire_driver(self, name, driver_id):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("localhost", 50051))

            hash_value = hashlib.sha256(driver_id.encode()).hexdigest()
            encrypted_hash = encrypt(self.client_private_key, hash_value)

            request_to_inquire = {
                "type_of_req": "Inquire",
                "driver_data": {
                    "name": name,
                    "driver_id": driver_id,
                    "hash": encrypted_hash,
                    "time": str(time.time())
                }
            }

            print("Sending inquiry request to server")
            sock.sendall(json.dumps(request_to_inquire).encode("utf-8"))
            response = sock.recv(8192)
            response_data = json.loads(response.decode("utf-8"))
            
            # Extract driver and validity from the response
            driver = decrypt(self.client_private_key,response_data.get("Driver"))
            validity = decrypt(self.client_private_key,response_data.get("validity"))
            
            # Print the extracted values
            print("Driver:", driver)
            print("Validity:", validity)


if __name__ == "__main__":
    client_id = str(uuid.uuid4())  # Generating a unique client ID
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
            police_client.register_driver(name, driver_id, dob)
        elif choice == 2:
            name = input("Enter name: ")
            driver_id = input("Enter Driver's ID: ")
            police_client.revoke_driver(name, driver_id)
        elif choice == 3:
            #   "0001": "Rohit|DL10-1234|" + str(time() + 2592000
            name = "Rohit"
            driver_id = "DL10-1234"
            police_client.inquire_driver(name, driver_id)

