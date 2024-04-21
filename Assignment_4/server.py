import socket
import threading
import json
from rsa import encrypt, decrypt
from time import time
import hashlib
# from assign_key import get_client_public_key, get_client_private_key, get_server_public_key, get_server_private_key

Database = {
    "0001": "Rohit|DL10-1234|" + str(time() + 2592000),
    "0002": "Abhinav|UP44-0001|" + str(time() + 2592500),
    "0003": "Aditya|HR32-1111|" + str(time() - 2592600),
    "0004": "Rahul|PB22-9999|" + str(time() + 2592700),
    "0005": "Kushagra|RJ11-6666|" + str(time() - 2592800)
}

class Server:
    def __init__(self, p, q):
        with open("keys.txt", "r") as file:
            lines = file.readlines()
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
        self.database = Database
        # print( self.client_public_key, self.client_private_key)
       

    def register_driver(self, driver_data):
        driver_id = str(len(self.database) + 1).zfill(4)  # Generating driver ID
        timestamp = str(time())  # Current timestamp
        driver_info = f"{driver_data['name']}|{driver_data['driver_id']}|{timestamp}"
        self.database[driver_id] = driver_info
        print("Driver registered successfully.")

    def revoke_driver(self, name, driver_id):
        to_delete = []
        for key, value in self.database.items():
            parts = value.split("|")
            if parts[0] == name and parts[1] == driver_id:
                to_delete.append(key)
        for key in to_delete:
            del self.database[key]
        print("Driver license revoked successfully.")

    def inquire_driver(self, driver_data,conn):
        driver_id = driver_data["driver_id"]
        encrypted_hash = driver_data["hash"]
        decrypted_hash = decrypt(self.client_public_key, encrypted_hash)
        name = driver_data["name"]
        current_timestamp = float(driver_data["time"])

        if decrypted_hash == hashlib.sha256(driver_id.encode()).hexdigest():
            flg=0
            for key, value in self.database.items():
                parts = value.split("|")
                if parts[0] == name and parts[1] == driver_id:
                    expiry_timestamp = float(parts[2])
                    flg=1
                    break
                    
            if(flg):
                print(expiry_timestamp,current_timestamp)
                if current_timestamp < expiry_timestamp:
                    validity = "Valid"
                else:
                    validity = "Expired"
                response = { "Driver": encrypt(self.client_public_key,"found"),
                    "validity": encrypt(self.client_public_key,validity)}
              
            else:
                 print("Driver not found in the database.")
                 response = { "Driver": encrypt(self.client_public_key,"Not Found"),
                    "validity": encrypt(self.client_public_key,"Invalid") }
            conn.sendall(json.dumps(response).encode())
               
        else:
            print("Hash verification failed. Possible tampering.")

def req_from_clients(conn, pkda):
    while True:
        data = conn.recv(8192)
        if not data:
            break
        print(f"Received data: {data}")
        request = json.loads(data.decode('utf-8'))

        if request["type_of_req"] == "Register":
            driver_data = request["driver_data"]
            pkda.register_driver(driver_data)
            response = {"message": "Driver registered successfully."}
            conn.sendall(json.dumps(response).encode())

        elif request["type_of_req"] == "Revoke":
            driver_data = request["driver_data"]
            name = driver_data["name"]
            driver_id = driver_data["driver_id"]
            pkda.revoke_driver(name, driver_id)
            response = {"message": "Driver license revoked successfully."}
            conn.sendall(json.dumps(response).encode())

        elif request["type_of_req"] == "Inquire":
            driver_data = request["driver_data"]
            pkda.inquire_driver(driver_data,conn)

    conn.close()

if __name__ == "__main__":
    try:
        pkda = Server(7, 13)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('localhost', 50051))
        server.listen(10)

        print("Server is listening for connections...")

        while True:
            connection, address = server.accept()
            print(f"New connection from {address}")
            threading.Thread(target=req_from_clients, args=(connection, pkda)).start()

    except KeyboardInterrupt:
        print("Server stopped by keyboard interrupt")
