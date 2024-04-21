from rsa import generate_key_pair

client_public_key, client_private_key = generate_key_pair(13, 17)
server_public_key, server_private_key = generate_key_pair(19, 23)



with open("keys.txt", "w") as file:
    file.write("Client Public Key:\n")
    file.write(str(client_public_key) )
    file.write("\nClient Private Key:\n")
    file.write(str(client_private_key) )
    file.write("\nServer Public Key:\n")
    file.write(str(server_public_key) )
    file.write("\nServer Private Key:\n")
    file.write(str(server_private_key) )
