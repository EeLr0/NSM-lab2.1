import ssl
import socket
from util.const import SERVER_HOST, SERVER_PORT

def startClient():
    context = ssl.create_default_context()
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock: #criar socket 
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock: # Encapsular socket com SSL/TLS
            print("Conexao segura com SSL/TLS")
            while True:
                msg = input("Escreva uma mensagem ou 'sair': ")
                if msg == 'sair':
                    break
                ssock.sendall(msg.encode())