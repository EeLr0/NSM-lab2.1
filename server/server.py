import socket, ssl, threading, bcrypt, json, os, time
from util.const import SERVER_HOST, SERVER_PORT
from util.keyexchange import generate_dh_parameters, serialize_dh_parameters

users_db = {}  # username: {"password": hash, "conn": socket, "dh_pub": bytes, "rsa_pub": bytes}
lock = threading.Lock()
shutdown_event = threading.Event()

# Carrega certificado
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
base_dir = os.path.dirname(os.path.abspath(__file__))
cert_path = os.path.join(base_dir, 'cert.pem')
key_path = os.path.join(base_dir, 'key.pem')
context.load_cert_chain(certfile=cert_path, keyfile=key_path)

# Gerar parâmetros DH fixos
DH_PARAMS = generate_dh_parameters()
DH_PARAMS_SERIALIZED = serialize_dh_parameters(DH_PARAMS)
print("Parâmetros DH globais gerados e serializados")

def client_thread(connstream):
    username = None
    try:
        mode = connstream.recv(1024).decode()
        print(f"[DEBUG] Modo recebido: '{mode}'")
        username = connstream.recv(1024).decode()
        print(f"[DEBUG] Usuário recebido: '{username}'")
        password = connstream.recv(1024).decode()
        print(f"[DEBUG] Senha recebida: {len(password)} caracteres")

        with lock:
            if mode == 'register':
                if username in users_db:
                    connstream.send(b"USER_EXISTS")
                    return
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                users_db[username] = {"password": hashed}
                connstream.send(b"REGISTER_OK")
                print(f"Usuário {username} registrado")
            elif mode == 'login':
                if username not in users_db or not bcrypt.checkpw(password.encode(), users_db[username]["password"]):
                    connstream.send(b"INVALID_CREDENTIALS")
                    return
                connstream.send(b"LOGIN_OK")
                print(f"Usuário {username} logado")
            else:
                connstream.send(b"INVALID_MODE")
                print(f"Modo inválido: '{mode}'")
                return

        # Envia parâmetros DH
        param_size = len(DH_PARAMS_SERIALIZED)
        connstream.send(param_size.to_bytes(4, byteorder='big'))
        connstream.send(DH_PARAMS_SERIALIZED)
        print(f"Parâmetros DH enviados para {username} ({param_size} bytes)")

        # Recebe chave DH
        key_size_bytes = connstream.recv(4)
        if len(key_size_bytes) != 4:
            print(f"Erro: tamanho inválido para chave DH de {username} ({len(key_size_bytes)} bytes)")
            return
        key_size = int.from_bytes(key_size_bytes, byteorder='big')
        if key_size > 1000000 or key_size <= 0:
            print(f"Erro: tamanho de chave DH inválido: {key_size} bytes")
            return
        print(f"Aguardando {key_size} bytes da chave DH de {username}...")
        client_dh_pub = b""
        while len(client_dh_pub) < key_size:
            chunk = connstream.recv(key_size - len(client_dh_pub))
            if not chunk:
                raise Exception("Conexão perdida durante recebimento da chave DH")
            client_dh_pub += chunk
        print(f"Chave DH de {username} recebida ({len(client_dh_pub)} bytes)")

        # Recebe chave RSA
        rsa_size_bytes = connstream.recv(4)
        if len(rsa_size_bytes) != 4:
            print(f"Erro: tamanho inválido para chave RSA de {username} ({len(rsa_size_bytes)} bytes)")
            return
        rsa_size = int.from_bytes(rsa_size_bytes, byteorder='big')
        if rsa_size > 1000000 or rsa_size <= 0:
            print(f"Erro: tamanho de chave RSA inválido: {rsa_size} bytes")
            return
        rsa_pub_bytes = b""
        while len(rsa_pub_bytes) < rsa_size:
            chunk = connstream.recv(rsa_size - len(rsa_pub_bytes))
            if not chunk:
                raise Exception("Conexão perdida durante recebimento da chave RSA")
            rsa_pub_bytes += chunk
        print(f"Chave RSA de {username} recebida ({len(rsa_pub_bytes)} bytes)")

        with lock:
            users_db[username]["conn"] = connstream
            users_db[username]["dh_pub"] = client_dh_pub
            users_db[username]["rsa_pub"] = rsa_pub_bytes

        # Recebe nome do peer
        peer_name = connstream.recv(1024).decode()
        print(f"{username} quer conversar com {peer_name}")

        # Espera o peer
        peer_dh_pub = None
        max_attempts = 60  # Aumentado para 60s
        for _ in range(max_attempts):
            with lock:
                if peer_name in users_db and "dh_pub" in users_db[peer_name]:
                    peer_dh_pub = users_db[peer_name]["dh_pub"]
                    break
            if _ == 0:
                connstream.send(b"WAITING_FOR_PEER")
            time.sleep(1)
            if shutdown_event.is_set():
                return

        if peer_dh_pub is None:
            connstream.send(b"PEER_NOT_AVAILABLE")
            print(f"Peer {peer_name} não ficou disponível em 60 segundos")
            return

        # Envia chave DH do peer
        peer_dh_size = len(peer_dh_pub)
        connstream.send(peer_dh_size.to_bytes(4, 'big'))
        connstream.send(peer_dh_pub)
        print(f"Chave DH de {peer_name} enviada para {username} ({peer_dh_size} bytes)")

        # Envia chave RSA do peer
        with lock:
            peer_rsa_pub = users_db[peer_name].get("rsa_pub", None)
        if peer_rsa_pub:
            peer_rsa_size = len(peer_rsa_pub)
            connstream.send(peer_rsa_size.to_bytes(4, 'big'))
            connstream.send(peer_rsa_pub)
            print(f"Chave RSA de {peer_name} enviada para {username} ({peer_rsa_size} bytes)")
        else:
            connstream.send((0).to_bytes(4, 'big'))
            print(f"Peer {peer_name} não tem chave RSA registrada")

        # Loop de mensagens
        while not shutdown_event.is_set():
            try:
                data = connstream.recv(16384)
                if not data:
                    break
                msg = json.loads(data.decode())
                to_user = msg["to"]
                with lock:
                    if to_user in users_db and "conn" in users_db[to_user]:
                        users_db[to_user]["conn"].send(data)
                    else:
                        print(f"Usuário {to_user} não está conectado")
            except json.JSONDecodeError as e:
                print(f"Erro ao decodificar JSON: {e}")
            except Exception as e:
                print(f"Erro no loop de mensagens: {e}")
                break

    except Exception as e:
        print(f"Erro com cliente {username}: {e}")
    finally:
        if username:
            with lock:
                if username in users_db:
                    users_db[username].pop("conn", None)
                    users_db[username].pop("dh_pub", None)
                    users_db[username].pop("rsa_pub", None)
            print(f"Cliente {username} desconectado")
        connstream.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((SERVER_HOST, SERVER_PORT))
            sock.listen(5)
            print(f"Servidor TLS ativo em {SERVER_HOST}:{SERVER_PORT}")
            while not shutdown_event.is_set():
                sock.settimeout(1.0)
                try:
                    conn, addr = sock.accept()
                    connstream = context.wrap_socket(conn, server_side=True)
                    threading.Thread(target=client_thread, args=(connstream,), daemon=True).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Erro ao aceitar conexão: {e}")
        except Exception as e:
            print(f"Erro ao iniciar servidor: {e}")
        finally:
            sock.close()

if __name__ == "__main__":
    main()