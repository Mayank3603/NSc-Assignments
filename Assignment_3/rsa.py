import random
import time
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    while e > 0:
        temp1 = temp_phi//e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        x2 = x1
        x1 = x
        d = y1
        y1 = y
    if temp_phi == 1:
        return d + phi

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def generate_key_pair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    n = p * q
    phi = (p-1) * (q-1)
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    key, n = pk
    aux = [str(pow(char, key, n)) for char in ciphertext]
    plain = [chr(int(char2)) for char2 in aux]
    return ''.join(plain)

class Client:
    def __init__(self, id, p, q, pkda):
        self.id = id
        self.pkda = pkda
        self.public_key, self.private_key = generate_key_pair(p, q)
        self.pkda_PU = self.pkda.public_key

    def encrypt(self, message):
        return encrypt(self.public_key, message)

    def decrypt(self, ciphertext):
        return decrypt(self.private_key, ciphertext)

    # def send_request(self, client_id):
    #     timestamp = str(int(time.time()))
    #     message = f"{self.id}-{client_id}-{timestamp}"
    #     encrypted_message = self.encrypt(message)
    #     self.pkda.receive_request(self.id, client_id, encrypted_message)

    # def receive_pkda_message(self, encrypted_message):
    #     decrypted_message = decrypt(self.pkda_PU, encrypted_message)
    #     print(f"Received PKDA message: {decrypted_message}")
        
class PKDA:
    def __init__(self, p, q):
        self.public_key, self.private_key = generate_key_pair(p, q)
        self.client_public_keys = {}
        self.client_instances = {}  # Store client instances

    # def register_client(self, client_id, public_key, client_instance):
    #     self.client_public_keys[client_id] = public_key
    #     self.client_instances[client_id] = client_instance  # Store client instance
    #     print(f"{client_id} has been registered")

    # def receive_request(self, sender_id, receiver_id, encrypted_message):
    #     if receiver_id not in self.client_public_keys:
    #         raise ValueError("Receiver ID not found")
    #     receiver_public_key = self.client_public_keys[receiver_id]
    #     decrypted_message = decrypt(receiver_public_key, encrypted_message)
    #     print(f"Received request from {sender_id} for {receiver_id} at {decrypted_message}")
    #     encrypted_response = encrypt(self.private_key, receiver_public_key)
    #     self.send_response(sender_id, encrypted_response)

    # def send_response(self, sender_id, encrypted_message):
    #     sender_public_key = self.client_public_keys[sender_id]
    #     sender_instance = self.client_instances[sender_id]  # Access client instance
    #     sender_instance.receive_pkda_message(encrypted_message)


# if __name__ == '__main__':
#     pkda = PKDA(13, 31)
#     client1 = Client("Client 1", 17, 19, pkda)
#     client2 = Client("Client 2", 23, 29, pkda)

#     client1_public_key = client1.public_key
#     client2_public_key = client2.public_key

#     pkda.register_client(client1.id, client1_public_key, client1)
#     pkda.register_client(client2.id, client2_public_key, client2)

#     print("Client 1 Public Key:", client1.public_key)
#     print("Client 1 Private Key:", client1.private_key)
#     print("Client 2 Public Key:", client2.public_key)
#     print("Client 2 Private Key:", client2.private_key)

#     # Client 1 sends a request to PKDA
#     client1.send_request(client2.id)

#     # PKDA sends a response to Client 1
#     encrypted_response = pkda.send_response(client1.id, client2.id)
#     decrypted_response = client1.decrypt(encrypted_response)
#     print("Decrypted response for Client 1:", decrypted_response)

if __name__ == '__main__':


    pkda=PKDA(13,31)
    client1 = Client("Client 1", 17, 19,pkda)
    client2 = Client("Client 2", 23, 29,pkda)
    
    client1_public_key = client1.public_key
    client2_public_key = client2.public_key
    
    # pkda.register_client(client1.id, client1_public_key)
    # pkda.register_client(client2.id, client2_public_key)



    print("Client 1 Public Key:", client1.public_key)
    print("Client 1 Private Key:", client1.private_key)
    print("Client 2 Public Key:", client2.public_key)
    print("Client 2 Private Key:", client2.private_key)


    message = "Hello,fad;ljfa;lkdjfal;dfja;kldjfalkdjfaldkjf4324324234234324234 world!"

    encrypted_msg_client1 = client1.encrypt(message)
    decrypted_msg_client1 = client1.decrypt(encrypted_msg_client1)
    print("Client 1 Encrypted Message:", encrypted_msg_client1)
    print("Client 1 Decrypted Message:", decrypted_msg_client1)

    encrypted_msg_client2 = client2.encrypt(message)
    decrypted_msg_client2 = client2.decrypt(encrypted_msg_client2)
    print("Client 2 Encrypted Message:", encrypted_msg_client2)
    print("Client 2 Decrypted Message:", decrypted_msg_client2)
