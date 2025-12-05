#from hmac import digest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import request, make_response, jsonify, redirect, url_for, abort
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
from base64 import b64encode, b64decode
import os

def gera_digest_senha(password):

    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
     
    digest = kdf.derive(password.encode("utf-8"))
    
    combinado = salt + digest  
    
    bash_base64_em_str = b64encode(combinado).decode('ascii')
    #hash_em_bytes_denovo = b64decode(bash_base64_em_str.encode('ascii'))
    #return b64encode(combinado).decode("ascii")
    return bash_base64_em_str

#Verificação da senha
def verifica_senha(password, senha_hash_base64):

    combinado = b64decode(senha_hash_base64.encode("ascii"))
    salt = combinado[:16]
    digest_real = combinado[16:]
    
    kdf = Scrypt(salt =salt, length =32, n=2**14, r=8, p=1, backend=default_backend())
    
    try:
        kdf.verify(password.encode("utf-8"), digest_real)
        return True
    except InvalidKey:
        return False



print(gera_digest_senha("senha1234"))

#print(verifica_senha("minha_senha_secreta",gera_digest_senha("minha_senha_secreta")))