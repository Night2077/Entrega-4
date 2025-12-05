import hashlib
from flask import Flask, json
from flask_sqlalchemy import SQLAlchemy
from flask import request, make_response, jsonify, redirect, url_for, abort
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidSignature
from base64 import b64encode, b64decode
import os
import requests

# 1 - Sistema de cadastro e autenticação de usuários

app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "users.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nome = db.Column(db.String(120), nullable=False)
    senha = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'

# Definição do Modelo de Sessão 1.3
class Session(db.Model):
    session_id = db.Column(db.String(32), primary_key=True) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 

#Derivando o digest da senha e codificando em Base64
def gera_digest_senha(password):
    print('senha original',password)
    salt = os.urandom(16)
    print('salt',salt)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend()) 
    digest = kdf.derive(password.encode("utf-8")) # derivar o digest da senha
    print('digest',digest)
    combinado = salt + digest  
    bash_base64_em_str = b64encode(combinado).decode('ascii') # codificar em Base64
    print('base64',bash_base64_em_str)
    return bash_base64_em_str

#Verificação da senha
def verifica_senha(password, senha_hash_base64):

    combinado = b64decode(senha_hash_base64.encode("ascii")) # decodificar de Base64 para bytes
    salt = combinado[:16]
    digest_real = combinado[16:]
    kdf = Scrypt(salt =salt, length =32, n=2**14, r=8, p=1, backend=default_backend())
    try:
        kdf.verify(password.encode("utf-8"), digest_real) # verificar a senha
        return True
    except InvalidKey:
        return False
    
#Geração do ID da Sessão
def gerar_session_id():
    random_bytes = os.urandom(16)
    return hashlib.md5(random_bytes).hexdigest()

#1.1 Cadastro de Usuário
@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "GET": # mostrar formulário de cadastro
        html = """
        <html>
        <body>
            <h2>Cadastro de Usuário</h2>
            <form action="/cadastro" method="POST">
                Email: <input type="email" name="email" required><br><br>
                Nome: <input type="text" name="nome" required><br><br>
                Senha: <input type="password" name="senha" required><br><br>
                <button type="submit">Cadastrar</button>
            </form>
        </body>
        </html>
        """
        return html, 200

    elif request.method == "POST":
        
         # Log do Content-Type recebido
        content_type = request.headers.get('Content-Type')
        print(f"Content-Type recebido: {content_type}")
        
        # Log dos dados brutos do corpo 
        print(f"Dados brutos do corpo: {request.get_data()}")
        
        # Obter dados do formulário
        email = request.form.get("email")
        nome = request.form.get("nome")
        senha = request.form.get("senha")
        
        # Log dos dados recebidos
        print(f"Dados recebidos - Email: {email}, Nome: {nome}, Senha: {senha}")

        # Verificar se email já existe
        usuario_existente = User.query.filter_by(email=email).first()
        if usuario_existente:
            return make_response("erro Email já cadastrado", 409)

        else:
            # Criação do usuário
            senha_hash = gera_digest_senha(senha) # hash da senha
            novo_usuario = User(email=email, nome=nome, senha=senha_hash)
            db.session.add(novo_usuario)
            db.session.commit()

            # Resposta 201 Created
            resposta = make_response("Usuário criado com sucesso!", 201)

        return resposta

#1.2 Login de Usuário
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET': # mostrar formulário de login
        return """
        <h2>Login</h2>
        <form method="POST" action="/login">
            email: <input type="email" name="email" required><br><br>
            senha: <input type="password" name="senha" required><br><br>
            <button type="submit">Entrar</button>
        </form>
        """, 200
    
    elif request.method == 'POST':
         # Log do Content-Type recebido
        if 'session_keys' in request.form and 'ciphertext' in request.form:
            try:
                # Extrair dados do formulário
                session_keys_b64 = request.form.get('session_keys')
                cyphertext_b64 = request.form.get('ciphertext')
                hmac_b64 = request.form.get('hmac')

                print(f"session_keys (base64): {session_keys_b64}")
                print(f"ciphertext (base64): {cyphertext_b64}")
                print(f"hmac (base64): {hmac_b64}")

                # Decodificar
                session_keys = b64decode(session_keys_b64)
                cyphertext = b64decode(cyphertext_b64)
                hmac_tag = b64decode(hmac_b64)

                # Extrair chaves
                aes_key = session_keys[0:32]
                mac_key = session_keys[32:64]
                iv = session_keys[64:80]

                # Verificar HMAC
                h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
                h.update(cyphertext)
                h.verify(hmac_tag)

                # Descriptografar AES-CTR
                cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(cyphertext) + decryptor.finalize()
                
                # Extrair email e senha do JSON
                login_data = json.loads(plaintext.decode('utf-8'))
                email = login_data.get('email')
                senha = login_data.get('password')

            except (InvalidSignature, ValueError, KeyError) as e: # Dados inválidos ou corrompidos
                print(f"Erro ao processar os dados criptografados: {e}")
                return abort(400, description="Dados inválidos ou corrompidos")

        user = User.query.filter_by(email=email).first() 

        if not user: # Usuário não encontrado
            return abort(401, description="Credenciais inválidas")
            
        if not verifica_senha(senha, user.senha): # Senha incorreta
            return abort(401, description="Credenciais inválidas")
            
        # Criar nova sessão
        session_id = gerar_session_id()
        sess = Session(session_id=session_id, user_id=user.id)
        db.session.add(sess)
        db.session.commit()

        # login bem sucedido 
        resp = make_response("Login OK!", 200)
        resp.set_cookie("session_id", session_id)  # setar cookie com ID da sessão
            
        #contenty_type
        print(f"content_type: {request.content_type}")
        print(f"session cookies: {session_id}")
        print(f"Email recebido: {email}")
        print(f"Senha recebida: {senha}")
        #print(f"User server: {user.senha}")

        return resp

#1.2 Logout de Usuário
@app.route("/logout", methods=["GET", "POST"])
def logout():

    if request.method == "GET": # mostrar formulário de logout
        return """
        <h2>Logout</h2>
        <form method="POST" action="/logout">
            <button type="submit">Sair</button>
        </form>
        """, 200

    if request.method == "POST":
        
        session_id = request.cookies.get("session_id")
        # Remover sessão do banco de dados
        if session_id:
            sess = Session.query.filter_by(session_id=session_id).first()
            if sess:
                db.session.delete(sess)
                db.session.commit()

        resp = make_response("Logout realizado", 200)
        resp.set_cookie("session_id", "X", max_age=0)   # apaga cookie
        return resp

# Página inicial
@app.route("/")
def home():

    session_id = request.cookies.get("session_id")

    if not session_id:
        return """
        <h1>Bem-vindo ao Portal Principal</h1>
        <p>Você não está logado.</p>
        <a href="/login"><button>Fazer Login</button></a>
        <a href="/cadastro"><button>Cadastrar</button></a>
        """, 200
    
    # Busca sessão no banco de dados
    sess = Session.query.filter_by(session_id=session_id).first()
    if not sess:
        return """
        <h1>Bem-vindo ao Portal Principal</h1>
        <p>Você não está logado.</p>
        <a href="/login"><button>Fazer Login</button></a>
        <a href="/cadastro"><button>Cadastrar</button></a>
        """, 200

    # Busca usuário da sessão
    user = User.query.get(sess.user_id)
    if not user:
        resp = make_response(redirect(url_for('login')))
        resp.set_cookie("session_id", "", max_age=0)
        return resp

    # página autenticada
    return f"""
    <h1>Bem-vindo, {user.nome}!</h1>
    <p>Email: {user.email}</p>
    <a href="/logout"><button>Sair</button></a>
    """, 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

