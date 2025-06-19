import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, simpledialog
import threading
import queue
import sys
import os
import builtins
from functools import partial

# Importa funções do projeto
try:
    from client.connection import start_client
    from server.server import main as start_server
    from util.const import SERVER_HOST, SERVER_PORT
except ImportError as e:
    print(f"Erro ao importar módulos: {e}")
    sys.exit(1)

# Fila para comunicação entre GUI e threads
input_queue = queue.Queue()
print_queue = queue.Queue()

# Função para redirecionar print
original_print = builtins.print
def custom_print(*args, **kwargs):
    message = ' '.join(map(str, args))
    print_queue.put(message)
    original_print(*args, **kwargs)

# Função para redirecionar input
def custom_input(prompt=''):
    if prompt:
        custom_print(prompt, end='')
    try:
        value = input_queue.get(timeout=180)  # Timeout de 180s
        custom_print(f"[DEBUG] Entrada fornecida para '{prompt.strip()}': {value}")
        return value
    except queue.Empty:
        custom_print(f"Erro: Timeout aguardando entrada para '{prompt.strip()}'")
        raise ValueError("Nenhuma entrada fornecida")

class AppGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Comunicação Segura")
        self.root.geometry("600x500")
        self.running = False
        self.mode = None
        self.client_thread = None
        self.server_thread = None
        self.auth_submitted = False
        self.waiting_for_peer = False
        self.messaging_enabled = False

        # Frame principal
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(pady=10, padx=10, fill='both', expand=True)

        # Seleção de modo (Cliente/Servidor)
        tk.Label(self.main_frame, text="Modo:").pack(anchor='w')
        self.mode_var = tk.StringVar(value="Cliente")
        tk.Radiobutton(self.main_frame, text="Cliente", variable=self.mode_var, value="Cliente", command=self.update_mode).pack(anchor='w')
        tk.Radiobutton(self.main_frame, text="Servidor", variable=self.mode_var, value="Servidor", command=self.update_mode).pack(anchor='w')

        # Configurações do Cliente
        self.client_config_frame = tk.Frame(self.main_frame)
        tk.Label(self.client_config_frame, text="Host:").pack(side='left')
        self.host_entry = tk.Entry(self.client_config_frame, width=15)
        self.host_entry.insert(0, SERVER_HOST)
        self.host_entry.pack(side='left', padx=5)
        tk.Label(self.client_config_frame, text="Porta:").pack(side='left')
        self.port_entry = tk.Entry(self.client_config_frame, width=10)
        self.port_entry.insert(0, str(SERVER_PORT))
        self.port_entry.pack(side='left', padx=5)
        tk.Label(self.client_config_frame, text="Modo:").pack(side='left')
        self.auth_mode = tk.StringVar(value="register")
        ttk.Combobox(self.client_config_frame, textvariable=self.auth_mode, values=["login", "register"], width=10, state='readonly').pack(side='left', padx=5)

        # Configurações do Servidor
        self.server_config_frame = tk.Frame(self.main_frame)
        tk.Label(self.server_config_frame, text="Porta:").pack(side='left')
        self.server_port_entry = tk.Entry(self.server_config_frame, width=10)
        self.server_port_entry.insert(0, str(SERVER_PORT))
        self.server_port_entry.pack(side='left', padx=5)

        # Botão de ação
        self.action_btn = tk.Button(self.main_frame, text="Iniciar Cliente", command=self.toggle_action)
        self.action_btn.pack(pady=5)

        # Área de log
        self.log_area = scrolledtext.ScrolledText(self.main_frame, height=15, width=60, state='disabled')
        self.log_area.pack(pady=5, fill='both', expand=True)

        # Frame de autenticação
        self.auth_frame = tk.Frame(self.main_frame)
        tk.Label(self.auth_frame, text="Usuário:").pack(side='left')
        self.username_entry = tk.Entry(self.auth_frame, width=15)
        self.username_entry.pack(side='left', padx=5)
        tk.Label(self.auth_frame, text="Senha:").pack(side='left')
        self.password_entry = tk.Entry(self.auth_frame, width=15, show='*')
        self.password_entry.pack(side='left', padx=5)
        self.auth_btn = tk.Button(self.auth_frame, text="Autenticar", command=self.submit_auth, state='disabled')
        self.auth_btn.pack(side='left', padx=5)

        # Frame de mensagens
        self.msg_frame = tk.Frame(self.main_frame)
        self.msg_entry = tk.Entry(self.msg_frame, width=50)
        self.msg_entry.pack(side='left', padx=5)
        self.send_btn = tk.Button(self.msg_frame, text="Enviar", command=self.send_message, state='disabled')
        self.send_btn.pack(side='left', padx=5)

        # Status label
        self.status_label = tk.Label(self.main_frame, text="Status: Desconectado", fg="red")
        self.status_label.pack(anchor='w', pady=5)

        # Atualiza modo inicial
        self.update_mode()

        # Inicia monitoramento de print
        self.root.after(100, self.check_print_queue)

    def update_mode(self):
        self.mode = self.mode_var.get()
        if self.mode == "Cliente":
            self.client_config_frame.pack(fill='x')
            self.server_config_frame.pack_forget()
            self.auth_frame.pack(fill='x', pady=5)
            self.msg_frame.pack(fill='x', pady=5)
            self.action_btn.config(text="Iniciar Cliente")
        else:
            self.client_config_frame.pack_forget()
            self.server_config_frame.pack(fill='x')
            self.auth_frame.pack_forget()
            self.msg_frame.pack_forget()
            self.action_btn.config(text="Iniciar Servidor")

    def toggle_action(self):
        if not self.running:
            if self.mode == "Cliente":
                try:
                    host = self.host_entry.get()
                    port = int(self.port_entry.get())
                    # Limpa input_queue
                    while not input_queue.empty():
                        try:
                            input_queue.get_nowait()
                        except queue.Empty:
                            break
                    self.auth_btn.config(state='normal')
                    self.running = True
                    self.action_btn.config(text="Parar Cliente")
                    self.status_label.config(text="Status: Conectando...", fg="orange")
                    # Redireciona print e input
                    builtins.print = custom_print
                    builtins.input = custom_input
                    # Inicia cliente em thread
                    self.client_thread = threading.Thread(target=self.run_client, args=(host, port), daemon=True)
                    self.client_thread.start()
                except ValueError:
                    messagebox.showerror("Erro", "Porta inválida!")
            else:
                try:
                    port = int(self.server_port_entry.get())
                    self.running = True
                    self.action_btn.config(text="Parar Servidor")
                    self.status_label.config(text="Status: Servidor ativo", fg="green")
                    # Redireciona print
                    builtins.print = custom_print
                    # Inicia servidor em thread
                    self.server_thread = threading.Thread(target=self.run_server, args=(port,), daemon=True)
                    self.server_thread.start()
                except ValueError:
                    messagebox.showerror("Erro", "Porta inválida!")
        else:
            self.running = False
            self.messaging_enabled = False
            self.action_btn.config(text="Iniciar Cliente" if self.mode == "Cliente" else "Iniciar Servidor")
            self.auth_btn.config(state='disabled')
            self.send_btn.config(state='disabled')
            self.status_label.config(text="Status: Desconectado", fg="red")
            # Restaura print e input
            builtins.print = original_print
            builtins.input = input
            # Para cliente
            if self.mode == "Cliente":
                input_queue.put('sair')
            # Para servidor
            if self.mode == "Servidor":
                try:
                    from server.server import shutdown_event
                    shutdown_event.set()
                except ImportError:
                    messagebox.showwarning("Aviso", "Servidor não suporta parada graciosa. Feche a janela.")

    def run_client(self, host, port):
        try:
            from util.const import SERVER_HOST as orig_host, SERVER_PORT as orig_port
            sys.modules['util.const'].SERVER_HOST = host
            sys.modules['util.const'].SERVER_PORT = port
            start_client()
            sys.modules['util.const'].SERVER_HOST = orig_host
            sys.modules['util.const'].SERVER_PORT = orig_port
        except Exception as e:
            custom_print(f"Erro no cliente: {e}")
            self.root.after(0, lambda: self.status_label.config(text=f"Status: Erro ({str(e)})", fg="red"))
        finally:
            self.running = False
            self.auth_submitted = False
            self.waiting_for_peer = False
            self.messaging_enabled = False
            self.root.after(0, lambda: self.action_btn.config(text="Iniciar Cliente"))
            self.root.after(0, lambda: self.auth_btn.config(state='disabled'))
            self.root.after(0, lambda: self.send_btn.config(state='disabled'))

    def run_server(self, port):
        try:
            from util.const import SERVER_PORT as orig_port
            sys.modules['util.const'].SERVER_PORT = port
            start_server()
            sys.modules['util.const'].SERVER_PORT = orig_port
        except Exception as e:
            custom_print(f"Erro no servidor: {e}")
            self.root.after(0, lambda: self.status_label.config(text=f"Status: Erro ({str(e)})", fg="red"))
        finally:
            self.running = False
            self.root.after(0, lambda: self.action_btn.config(text="Iniciar Servidor"))

    def submit_auth(self):
        mode = self.auth_mode.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not mode or not username or not password:
            messagebox.showwarning("Aviso", "Preencha todos os campos!")
            return
        self.auth_submitted = True
        custom_print(f"[DEBUG] Autenticando: modo={mode}, usuário={username}, senha={password}")
        input_queue.put(mode)
        input_queue.put(username)
        input_queue.put(password)
        self.auth_btn.config(state='disabled')

    def send_message(self):
        message = self.msg_entry.get()
        if message:
            custom_print(f"[DEBUG] Enviando mensagem: {message}")
            input_queue.put(message)
            self.msg_entry.delete(0, tk.END)

    def check_print_queue(self):
        try:
            while True:
                message = print_queue.get_nowait()
                self.log_area.config(state='normal')
                self.log_area.insert(tk.END, f"{message}\n")
                self.log_area.config(state='disabled')
                self.log_area.yview(tk.END)
                # Verifica prompt de peer
                if "Deseja conversar com (username):" in message and not self.waiting_for_peer:
                    self.waiting_for_peer = True
                    self.root.after(0, self.prompt_for_peer)
                # Verifica conexão estabelecida
                if "Conexão estabelecida!" in message and not self.messaging_enabled:
                    self.messaging_enabled = True
                    self.root.after(0, lambda: self.status_label.config(text="Status: Conectado", fg="green"))
                    self.root.after(0, lambda: self.send_btn.config(state='normal'))
                    custom_print("[DEBUG] Modo de mensagens ativado")
        except queue.Empty:
            pass
        self.root.after(100, self.check_print_queue)

    def prompt_for_peer(self):
        peer = simpledialog.askstring("Selecionar Peer", "Digite o nome do usuário para conversar:", parent=self.root)
        if peer:
            custom_print(f"[DEBUG] Peer selecionado: {peer}")
            input_queue.put(peer)
            self.status_label.config(text="Status: Aguardando peer...", fg="orange")
        else:
            messagebox.showwarning("Aviso", "Peer não especificado. Conexão será encerrada.")
            input_queue.put('sair')

def main():
    print("Iniciando interface gráfica...")
    root = tk.Tk()
    app = AppGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()