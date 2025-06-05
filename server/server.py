import ssl
import socket
from util.const import SERVER_HOST, SERVER_PORT
#from server.auth import handle_login_or_register

def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='certs/server.crt', keyfile='certs/server.key')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((SERVER_HOST, SERVER_PORT))
        sock.listen(5)
        print("Servidor TLS pronto para conexões")
        while True:
            client_sock, addr = sock.accept()
            with context.wrap_socket(client_sock, server_side=True) as ssock:
                #print(f"Conexão recebida de {addr}")
                #authenticated = handle_login_or_register(ssock)
                #if authenticated:
                    while True:
                        data = ssock.recv(1024)
                        if not data:
                            break
                        print(f"Mensagem de {addr}: {data.decode()}")