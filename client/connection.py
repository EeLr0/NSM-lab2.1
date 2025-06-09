import ssl, socket, threading, json, sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.const import SERVER_HOST, SERVER_PORT
from util.protocol import createMessage
from cryptography.hazmat.primitives import serialization
from client.crypto import encrypt_message, decrypt_message, sign_message, verify_signature
from client.keymanager import generate_rsa_keypair
from util.keyexchange import (generate_dh_keypair, compute_shared_key, deserialize_dh_parameters, 
                              serialize_dh_public_key, deserialize_dh_public_key, validate_dh_key_pair)


shared_key = None
username = None
private_key = None
peer_public_rsa = None

def listen_for_messages(ssock):
    global shared_key, peer_public_rsa
    while True:
        try:
            data = ssock.recv(4096)
            if not data:
                break
            message = json.loads(data.decode())
            nonce = bytes.fromhex(message['nonce'])
            ciphertext = bytes.fromhex(message['ciphertext'])
            signature = bytes.fromhex(message['signature'])
            sender = message['from']
            decrypted = decrypt_message(shared_key, nonce, ciphertext)

            if not verify_signature(peer_public_rsa, decrypted.encode(), signature):
                print(f"\nAssinatura inválida de {sender}. Mensagem descartada.")
                continue

            print(f"\nMensagem de {sender}: {decrypted}")
        except Exception as e:
            print(f"Erro ao receber mensagem: {e}")
            break

def recv_exact(sock, num_bytes):
    data = b''
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet:
            raise ConnectionError("Conexão encerrada prematuramente")
        data += packet
    return data


def start_client():
    global shared_key, username, private_key, peer_public_rsa

    print('cliente iniciado')

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            print("Conectado com TLS ao servidor")

            mode = input("Digite 'login' ou 'register': ")
            ssock.send(mode.encode())
            username = input("Nome de utilizador: ")
            ssock.send(username.encode())
            senha = input("Senha: ")
            ssock.send(senha.encode())

            resposta = ssock.recv(1024)
            if resposta == b"USER_EXISTS":
                print("Usuário já existe.")
                return
            elif resposta == b"INVALID_CREDENTIALS":
                print("Credenciais inválidas.")
                return
            elif resposta == b"INVALID_MODE":
                print("Modo inválido.")
                return
            else:
                print("Autenticação feita com sucesso.")

            try:
                param_size_bytes = ssock.recv(4)
                param_size = int.from_bytes(param_size_bytes, byteorder='big')
                print(f"Aguardando {param_size} bytes de parâmetros DH...")

                dh_params_data = b""
                while len(dh_params_data) < param_size:
                    chunk = ssock.recv(param_size - len(dh_params_data))
                    if not chunk:
                        raise Exception("Conexão perdida durante recebimento dos parâmetros DH")
                    dh_params_data += chunk

                print("Parâmetros DH recebidos, deserializando...")
                dh_parameters = deserialize_dh_parameters(dh_params_data)
                print("Parâmetros DH deserializados com sucesso")

                private_dh, public_dh = generate_dh_keypair(dh_parameters)
                print("Par de chaves DH gerado")

                if not validate_dh_key_pair(private_dh, public_dh, dh_parameters):
                    raise Exception("Validação do par de chaves DH falhou")

                public_dh_bytes = serialize_dh_public_key(public_dh)
                print(f"Enviando chave pública DH ({len(public_dh_bytes)} bytes)")
                key_size = len(public_dh_bytes)
                ssock.send(key_size.to_bytes(4, byteorder='big'))
                ssock.send(public_dh_bytes)
                print("Chave pública DH enviada")

                # Gera e envia chave RSA pública
                private_key, public_key = generate_rsa_keypair()
                rsa_pub_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                ssock.send(len(rsa_pub_bytes).to_bytes(4, 'big'))
                ssock.send(rsa_pub_bytes)

                peer_name = input("Deseja conversar com (username): ")
                ssock.send(peer_name.encode())

                response_size_bytes = recv_exact(ssock, 4)
                response_size = int.from_bytes(response_size_bytes, byteorder='big')
                print(f"Aguardando {response_size} bytes da chave do peer...")
                response = recv_exact(ssock, response_size)

                if b"PEER_NOT_AVAILABLE" in response:
                    print("Peer não disponível. Certifique-se de que o usuário está conectado.")
                    return

                peer_public_key = deserialize_dh_public_key(response)
                shared_key_raw = compute_shared_key(private_dh, peer_public_key)
                shared_key = shared_key_raw[:32]
                print(f"Chave compartilhada derivada com sucesso. Tamanho: {len(shared_key)} bytes")

                # Recebe chave RSA do peer
                rsa_size_bytes = ssock.recv(4)
                rsa_size = int.from_bytes(rsa_size_bytes, 'big')
                if rsa_size > 0:
                    peer_rsa_pub_bytes = ssock.recv(rsa_size)
                    peer_public_rsa = serialization.load_pem_public_key(peer_rsa_pub_bytes)
                    print("Chave RSA do peer recebida com sucesso")
                else:
                    print("AVISO: chave RSA do peer não foi fornecida")
                    peer_public_rsa = None

            except Exception as e:
                print(f"Erro durante troca de chaves DH/RSA: {e}")
                return

            threading.Thread(target=listen_for_messages, args=(ssock,), daemon=True).start()

            print("Conexão estabelecida! Digite mensagens ou 'sair' para encerrar.")
            while True:
                msg = input("Mensagem: ")
                if msg.lower() == 'sair':
                    break
                    
                try:
                    nonce, ciphertext = encrypt_message(shared_key, msg.encode())
                    signature = sign_message(private_key, msg.encode())
                    proto_msg = createMessage(username, peer_name, ciphertext, nonce, signature)
                    ssock.send(json.dumps(proto_msg).encode())
                except Exception as e:
                    print(f"Erro ao enviar mensagem: {e}")