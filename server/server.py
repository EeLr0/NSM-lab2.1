import socket, ssl, threading, bcrypt, json, os, subprocess
from util.const import SERVER_HOST, SERVER_PORT

users_db = {}  # username: {"password": hash, "conn": socket, "dh_pub": bytes}
lock = threading.Lock()

# Gerar certificado e chave se não existirem
if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
    print("🔒 Certificado ou chave não encontrados. Gerando automaticamente...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", "key.pem", "-out", "cert.pem",
        "-days", "365", "-nodes", "-subj", "/CN=localhost"
    ], check=True)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

def client_thread(connstream):
    try:
        mode = connstream.recv(1024).decode()
        username = connstream.recv(1024).decode()
        password = connstream.recv(1024).decode()

        with lock:
            if mode == 'register':
                if username in users_db:
                    connstream.send("Usuário já existe.".encode())
                    return
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                users_db[username] = {"password": hashed}
                connstream.send("Registro com sucesso.".encode())
            elif mode == 'login':
                if username not in users_db or not bcrypt.checkpw(password.encode(), users_db[username]["password"]):
                    connstream.send("Credenciais inválidas.".encode())
                    return
                connstream.send("Login com sucesso.".encode())
            else:
                connstream.send("Modo inválido.".encode())
                return

        # Troca de chave DH
        client_dh_pub = connstream.recv(8192)  # bytes PEM
        with lock:
            users_db[username]["conn"] = connstream
            users_db[username]["dh_pub"] = client_dh_pub

        peer_name = connstream.recv(1024).decode()
        with lock:
            if peer_name not in users_db or "dh_pub" not in users_db[peer_name]:
                connstream.send("Peer não disponível.".encode())
                return
            peer_dh_pub = users_db[peer_name]["dh_pub"]
        connstream.send(peer_dh_pub)

        while True:
            data = connstream.recv(16384)
            if not data:
                break
            msg = json.loads(data.decode())
            to_user = msg["to"]
            with lock:
                if to_user in users_db and "conn" in users_db[to_user]:
                    users_db[to_user]["conn"].send(data)
    except Exception as e:
        print("Erro com cliente:", e)
    finally:
        connstream.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((SERVER_HOST, SERVER_PORT))
    sock.listen(5)
    print(f"Servidor TLS ativo em {SERVER_HOST}:{SERVER_PORT}")
    while True:
        conn, addr = sock.accept()
        connstream = context.wrap_socket(conn, server_side=True)
        threading.Thread(target=client_thread, args=(connstream,), daemon=True).start()