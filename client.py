from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import requests
import base64
import sys
import os
import json

class EncryptionManager:
    def __init__(self):
        self.aes_key = os.urandom(32)   # chave AES-256
        self.mac_key = os.urandom(32)   # chave para HMAC-SHA256
        self.iv = os.urandom(16)     # IV para AES-CTR
        self.cipher = Cipher(algorithms.AES(self.aes_key),modes.CTR(self.iv),backend=default_backend())

    def encrypt(self, plaintext):
        encryptor = self.cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()
    
    def decrypt(self, ciphertext):
        decryptor = self.cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def calculate_hmac(self, data):
        h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()

    def get_keys_concatenated(self):
        # AES_KEY (32) + HMAC_KEY (32) + NONCE (16)
        return self.aes_key + self.mac_key + self.iv

class TransmissionManager:
    def __init__(self):
        self.private_key = None # chave privada para assinar
        self.public_key = None # chave pública para criptografar
        
    def encrypt_with_public_key(self, data, public_key):
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt_with_private_key(self, ciphertext, private_key):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
        


def client(email, password, arquivo):

        # Cria gerenciadores
        encry = EncryptionManager()
        encrypt = TransmissionManager()

        # load chave publica
        with open("my_key_pub.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        # gera chaves rsa
        session_key = encry.get_keys_concatenated()

        encry_session_key = encrypt.encrypt_with_public_key(session_key, public_key)    

        # Prepara os dados brutos (Plaintext) como JSON
        login_payload = json.dumps({"email": email, "password": password}).encode('utf-8')

        # 3. Encriptação Simétrica (AES-CTR)
        cipher = Cipher(algorithms.AES(encry.aes_key), modes.CTR(encry.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(login_payload) + encryptor.finalize()

        # 4. Calcular HMAC do texto cifrado (Encrypt-then-MAC)
        h = hmac.HMAC(encry.mac_key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        hmac_signature = h.finalize()
        
        # Encode em Base64
        session_keys_b64 = base64.b64encode(encry_session_key).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        hmac_b64 = base64.b64encode(hmac_signature).decode('utf-8')

        # Imprimir dados para o relatório (conforme solicitado)
        print("--- Dados da Requisição (Debug) ---")
        print(f"Session Keys (B64): {session_keys_b64}")
        print(f"Ciphertext (B64): {ciphertext_b64}")
        print(f"HMAC (B64): {hmac_b64}")
        print("-----------------------------------")

        # 6. Realizar a requisição POST
        url = 'http://localhost:5000/login'
        data = {
            'session_keys': session_keys_b64,
            'ciphertext': ciphertext_b64,
            'hmac': hmac_b64
        }

        try:
            r = requests.post(url, data=data) 
            print(f"\nStatus Code: {r.status_code}")
            if r.status_code == 200:
                if 'session_id' in r.cookies:
                    print(f"Login Bem Sucedido! Session ID: {r.cookies['session_id']}")
                else:
                    print("Login realizado, mas nenhum cookie session_id retornado.")
            else:
                print(f"Falha no login: {r.text}")
        except requests.exceptions.ConnectionError:
            print("Erro: Não foi possível conectar ao servidor. Verifique se ele está rodando.")

   
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python client.py <email> <password> <arquivo>")
        sys.exit(1)
    client(sys.argv[1], sys.argv[2],sys.argv[3])



