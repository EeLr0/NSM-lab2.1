# Sistema Seguro de Comunicação

Este projeto implementa um sistema de mensagens encriptadas ponto-a-ponto, com autenticação, sigilo e integridade, utilizando uma arquitetura cliente-servidor. O sistema suporta:

- **Criptografia**: Diffie-Hellman (DH-2048) para troca de chaves, AES-256-GCM para cifragem, RSA-PSS para assinaturas digitais.
- **Segurança**: TLS 1.2+ para comunicação cliente-servidor, autenticação via bcrypt.
- **Interfaces**: CLI (`main.py`) e GUI estilizada em Tkinter (`interface.py`) com logs coloridos e status dinâmico.

O servidor atua como intermediário, encaminhando mensagens sem acesso ao conteúdo, garantindo privacidade ponta-a-ponta.

## Pré-requisitos

- **Sistema Operacional**: Linux, macOS ou Windows.
- **Python**: Versão 3.8 ou superior.
- **Dependências**:
  ```bash
  pip install cryptography==38.0.1 bcrypt==4.0.1
  ```
  - Para GUI, instale Tkinter:
    ```bash
    # Linux
    sudo apt-get install python3-tk
    # macOS (geralmente já incluso)
    # Windows (incluso no Python)
    ```
- **Porta**: Certifique-se de que a porta 8000 está livre:
  ```bash
  # Linux/macOS
  sudo lsof -i :8000
  # Windows
  netstat -aon | findstr :8000
  ```
  Mate processos na porta, se necessário:
  ```bash
  kill -9 <PID>  # Linux/macOS
  taskkill /PID <PID> /F  # Windows
  ```

## Estrutura de Arquivos

Certifique-se de que os seguintes arquivos estão no diretório do projeto:

```
├── client/
│   ├── main.py           # Ponto de entrada CLI
│   ├── connection.py     # Conexão TLS e troca de mensagens
│   ├── crypto.py         # AES-GCM e RSA-PSS
│   ├── keymanager.py     # Geração de chaves RSA
├── server/
│   ├── server.py         # Lógica do servidor
│   ├── cert.pem          # Certificado TLS autoassinado
│   ├── key.pem           # Chave privada TLS
├── util/
│   ├── certgenerator.py  # Gera certificados TLS
│   ├── const.py          # Constantes (ex.: SERVER_PORT=8000)
│   ├── keyexchange.py    # Diffie-Hellman
│   ├── protocol.py       # Formato das mensagens
├── interface.py          # Interface gráfica Tkinter
├── requirements.txt      # Dependências
```

## Instalação

1. Clone ou extraia o projeto:
   ```bash
   git clone https://github.com/seu-repositorio.git
   cd seu-repositorio
   ```

2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

3. Gere certificados TLS, se necessário:
   ```bash
   python util/certgenerator.py
   ```
   Isso cria `cert.pem` e `key.pem` na pasta `server/`.

## Como Rodar (GUI)

Siga os passos abaixo para executar o sistema usando a interface gráfica (`interface.py`).

1. **Iniciar o Servidor**:
   - Abra um terminal e execute:
     ```bash
     python interface.py
     ```
   - Na GUI:
     - Selecione **Servidor**.
     - Confirme a porta **8000**.
     - Clique em **Iniciar Servidor**.
   - Log esperado: `Servidor TLS ativo em localhost:8000`.
   - Status na GUI: `Status: Servidor ativo` (verde).

2. **Iniciar Cliente 1 (bob)**:
   - Abra um segundo terminal e execute:
     ```bash
     python interface.py
     ```
   - Na GUI:
     - Selecione **Cliente**.
     - Host: `localhost`, Porta: `8000`.
     - Modo: `register` (ou `login` se já registrado).
     - Preencha:
       - Usuário: `bob`
       - Senha: `123`
     - Clique em **Autenticar**.
     - No prompt `Deseja conversar com (username):`, digite `alice`.
   - Log esperado: `Conexão estabelecida!`.
   - Status na GUI: `Status: Conectado` (verde).

3. **Iniciar Cliente 2 (alice)**:
   - Abra um terceiro terminal e repita o passo 2, mas com:
     - Usuário: `alice`
     - Senha: `123`
     - Peer: `bob`
   - Log esperado: `Conexão estabelecida!`.

4. **Trocar Mensagens**:
   - Na GUI de `bob`:
     - Digite `ola alice sou bob` no campo de mensagem.
     - Clique em **Enviar**.
     - Log: `[DEBUG] Enviando mensagem: ola alice sou bob` (azul).
   - Na GUI de `alice`:
     - Veja `Mensagem de bob: ola alice sou bob` (verde).
     - Responda (ex.: `ola bob`) e verifique em `bob`.

## Como Rodar (CLI)

Para usar a interface de linha de comando, siga os passos abaixo.

1. **Iniciar o Servidor**:
   ```bash
   python -m server.server
   ```
   - Log esperado: `Servidor TLS ativo em localhost:8000`.

2. **Iniciar Cliente 1 (bob)**:
   ```bash
   python client/main.py
   ```
   - No prompt:
     - Modo: `register`
     - Usuário: `bob`
     - Senha: `123`
     - Peer: `alice`
   - Log esperado: `Conexão estabelecida!`.

3. **Iniciar Cliente 2 (alice)**:
   - Repita o passo 2, mas com:
     - Usuário: `alice`
     - Senha: `123`
     - Peer: `bob`

4. **Trocar Mensagens**:
   - Em `bob`, digite `ola alice sou bob` e pressione Enter.
   - Em `alice`, veja `Mensagem de bob: ola alice sou bob` e responda.



## Contato

Para dúvidas ou problemas, contate:
- Eduardo Ramos
- Ednilson Rodrigues
- Fabio Monteiro
- Orientador: Estanislau Lima
