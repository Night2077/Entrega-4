from flask import request, make_response, jsonify, redirect, url_for, abort
from database_test import app, db, User #, Session

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

#1.2 Login de Usuário

@app.route('/login', methods=['GET', 'POST'])
def fake_login():
    if request.method == 'GET': # mostrar formulário de login
        return """
        <h2>Login</h2>
        <form method="POST" action="/login">
            email: <input type="email" name="email" required><br><br>
            senha: <input type="password" name="senha" required><br><br>
            <button type="submit">Entrar</button>
        </form>
        """, 200
    
    if request.method == "POST":
        email = request.form.get("email")
        senha = request.form.get("senha")
        user = User.query.filter_by(email=email, senha=senha).first() # buscar usuário no banco de dados

        if not user: 
            return abort(401, description="Credenciais inválidas")

        # login bem sucedido 
        resp = make_response("Login OK!", 200)
        resp.set_cookie("user_id", str(user.id))  # setar cookie com ID do usuário

        print(f"content_type: {request.content_type}")
        print(f"Email recebido: {email}")
        print(f"Senha recebida: {senha}")

        return resp

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
        resp = make_response("Logout realizado", 200)
        resp.set_cookie("user_id", "X", max_age=0)   # apaga cookie
        return resp

#@app.route('/delete-cookie')
#def delete_cookie():
#    res.set_cookie('user', 'qualquer_coisa', max_age=0)
#    return res 

# Página inicial
@app.route("/")
def home():
    user_id = request.cookies.get("user_id")
    if not user_id or user_id == "X": # Redireciona para login se não estiver autenticado
        return """
        <html>
        <head><title>Portal Principal</title></head>
        <body>
            <h1>Bem-vindo ao Portal Principal</h1>
            <p>Você não está logado.</p>
            <a href="/login"><button>Fazer Login</button></a>
            <a href="/cadastro"><button>Cadastrar</button></a>
        </body>
        </html>
        """, 200
    
    user = User.query.get(user_id) # buscar usuário no banco de dados
    if not user: # Cookie inválido - redireciona para login
        resp = make_response(redirect(url_for('login')))
        resp.set_cookie("user_id", "", max_age=0)
        return resp

    # Usuário autenticado - mostrar página principal
    return f"""
    <html>
    <head><title>Portal Principal</title></head>
    <body>
        <h1>Bem-vindo, {user.nome}!</h1>
        <p>Email: {user.email}</p>
        <a href="/logout"><button>Sair</button></a>
    </body>
    </html>
    """, 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

