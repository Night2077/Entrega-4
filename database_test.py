from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# Configuração do caminho do banco de dados SQLite
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "users.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Inicialização do SQLAlchemy
db = SQLAlchemy(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nome = db.Column(db.String(120), nullable=False)
    senha = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'


# Definição do Modelo de Sessão (Necessário para a Parte 1.3)
# Você pode descomentar isso quando chegar na parte 1.3

#class Session(db.Model):
#    session_id = db.Column(db.String(32), primary_key=True)
#    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    


#testando o git 
