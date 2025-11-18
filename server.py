
from flask import Flask, request, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# Configuração do banco SQLite local
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "users.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nome = db.Column(db.String(120), nullable=False)
    senha = db.Column(db.String(120), nullable=False)

# Criar tabelas caso não existam
with app.app_context():
    db.create_all()

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "GET":
        # Resposta GET com formulário HTML
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
        
        # Log dos dados brutos do corpo (para debug)
        print(f"Dados brutos do corpo: {request.get_data()}")
        
        # Obter dados do formulário
        email = request.form.get("email")
        nome = request.form.get("nome")
        senha = request.form.get("senha")
        
        # Log dos dados recebidos
        print(f"Dados recebidos - Email: {email}, Nome: {nome}, Senha: {senha}")

        # Validação básica dos campos
        if not all([email, nome, senha]):
            return make_response(jsonify({
                "erro": "Todos os campos (email, nome, senha) são obrigatórios"
            }), 400)

        # Verificar se email já existe
        usuario_existente = User.query.filter_by(email=email).first()
        if usuario_existente:
            return make_response(jsonify({
                "erro": "Email já cadastrado"
            }), 409)

        else:
            # Criação do usuário
            novo_usuario = User(email=email, nome=nome, senha=senha)
            db.session.add(novo_usuario)
            db.session.commit()

            # Resposta 201 Created
            resposta = make_response("Usuário criado com sucesso!", 201)

        return resposta

if __name__ == "__main__":
    app.run(debug=True)

#teste