import socket
import threading
import json
from rsa import encrypt, decrypt
from time import time
import hashlib

Database = {
    "0001": "Rohit|DL10-1234|" + str(time() + 2592000) + "|" + "12345" + "|" + "1234",
    "0002": "Abhinav|UP44-0001|" + str(time() + 2592500) + "|" + "88888" + "|" + "2345",
    "0003": "Aditya|HR32-1111|" + str(time() - 2592600) + "|" + "54321" + "|" + "3456",
    "0004": "Rahul|PB22-9999|" + str(time() + 2592700) + "|" + "12378" + "|" + "4567",
    "0005": "Kushagra|RJ11-6666|" + str(time() - 2592800) + "|" +"55555" + "|" + "5678"
}

class Server:
    def __init__(self, p, q):
        with open('keys.txt', 'r') as file:
            lines = file.readlines()

        self.client_public_key = tuple(int(x) for x in lines[1].strip()[1:-1].split(','))
        self.server_public_key = tuple(int(x) for x in lines[5].strip()[1:-1].split(','))
        self.server_private_key = tuple(int(x) for x in lines[7].strip()[1:-1].split(','))

        print("Client Public Key:", self.client_public_key)
        print("Server Public Key:", self.server_public_key)
        print("Server Private Key:", self.server_private_key)
        self.database = Database
       

    def register_driver(self, driver_data):
        driver_id = str(len(self.database) + 1).zfill(4) 
        timestamp = str(time())  
        driver_info = f"{driver_data['name']}|{driver_data['driver_id']}|{timestamp}|{driver_data['finger_print']}|{driver_data['certificate']}"
        self.database[driver_id] = driver_info
        print("Driver registered successfully.")
        print(self.database)

    def revoke_driver(self, name, driver_id, fingerprint, certificate):
        to_delete = []
        for key, value in self.database.items():
            parts = value.split("|")
            if parts[0] == name and parts[1] == driver_id and parts[3]==fingerprint and parts[4]==certificate:
                to_delete.append(key)
        
        for key in to_delete:
            del self.database[key]
        print("Driver license revoked successfully.")
        print(self.database)

    def inquire_driver(self, driver_data,conn):
        driver_id = driver_data["driver_id"]
        encrypted_hash = driver_data["hash"]
        decrypted_hash = decrypt(self.client_public_key, encrypted_hash)
        name = driver_data["name"]
        fingerprint = driver_data["finger_print"]
        certificate = driver_data["certificate"]
        current_timestamp = float(driver_data["time"])
        decoded = name+driver_id+fingerprint+certificate
        if decrypted_hash == hashlib.sha256(decoded.encode()).hexdigest():
            flg=0
            for key, value in self.database.items():
                parts = value.split("|")
                if parts[0] == name and parts[1] == driver_id and parts[3]==fingerprint and parts[4]==certificate:
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
            fingerprint = driver_data["finger_print"]
            certificate = driver_data["certificate"]
            pkda.revoke_driver(name, driver_id, fingerprint, certificate)
            response = {"message": "Driver license revoked successfully."}
            conn.sendall(json.dumps(response).encode())

        elif request["type_of_req"] == "Inquire":
            driver_data = request["driver_data"]
            pkda.inquire_driver(driver_data,conn)

    conn.close()

if __name__ == "__main__":
    try:
        transport_server = Server(7, 13)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('localhost', 50051))
        server.listen(10)
        

        print("Server is listening for connections...")

        while True:
            connection, address = server.accept()
            print(f"New connection from {address}")
            threading.Thread(target=req_from_clients, args=(connection, transport_server)).start()

    except KeyboardInterrupt:
        print("Server stopped by keyboard interrupt")
