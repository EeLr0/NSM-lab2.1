import ssl
import socket
import threading
import json
from util.const import SERVER_HOST, SERVER_PORT
from util.protocol import create_message
from client.crypto import encrypt_message, decrypt_message, sign_message, verify_signature
from client.keymanager import generate_rsa_keypair
from util.keyexchange import generate_dh_parameters, generate_dh_keypair, compute_shared_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
import base64

shared_key = None
username = None
private_key = None
peer_public_rsa = None  # 🆕 Chave pública do emissor

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

            # ✅ Verifica assinatura digital
            if not verify_signature(peer_public_rsa, decrypted.encode(), signature):
                print(f"\n⚠️ Assinatura inválida de {sender}. Mensagem descartada.")
                continue

            print(f"\n📥 Mensagem de {sender}: {decrypted}")
        except Exception as e:
            print(f"Erro ao receber mensagem: {e}")
            break

def start_client():
    global shared_key, username, private_key, peer_public_rsa

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
            resposta = ssock.recv(1024).decode()
            print(resposta)
            if "sucesso" not in resposta:
                return

            dh_parameters = generate_dh_parameters()
            private_dh, public_dh = generate_dh_keypair(dh_parameters)
            ssock.send(public_dh.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            peer_name = input("Deseja conversar com (username): ")
            ssock.send(peer_name.encode())

            # Recebe chave pública DH do peer
            peer_public_bytes = ssock.recv(8192)
            peer_public_key = load_der_public_key(peer_public_bytes)
            shared_key = compute_shared_key(private_dh, peer_public_key)[:32]

            # Gera par RSA e envia chave pública (futuramente)
            private_key, public_key = generate_rsa_keypair()

            # 🆕 Solicita chave RSA do peer
            print(f"Solicitando chave RSA pública de {peer_name}...")
            # Aqui você pode implementar a lógica para envio/recebimento da chave RSA
            # Por ora, simula-se que a chave está carregada localmente
            # peer_public_rsa = load_peer_rsa_public_key_from_server()
            print("⚠️ AVISO: chave RSA do peer não recebida do servidor. A verificação funcionará apenas se configurada manualmente.")
            peer_public_rsa = public_key  # Substitua isso pela chave correta

            threading.Thread(target=listen_for_messages, args=(ssock,), daemon=True).start()

            while True:
                msg = input("Digite a mensagem (ou 'sair'): ")
                if msg == 'sair':
                    break
                nonce, ciphertext = encrypt_message(shared_key, msg.encode())
                signature = sign_message(private_key, msg.encode())
                proto_msg = create_message(username, peer_name, ciphertext, nonce, signature)
                ssock.send(json.dumps(proto_msg).encode())
