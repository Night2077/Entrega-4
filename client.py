from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import requests
import base64
import sys
import os
import json


class EncryptionManager:
    def __init__(self):
        self.key = os.urandom(32) # Chave AES-256
        self.nonce = os.urandom(16) # AES-CTR nonce
        self.aes_context = Cipher(algorithms.AES(self.key), modes.CTR(self.nonce), backend=default_backend()) # AES-CTR
        self.encryptor = self.aes_context.encryptor() # Criptografar
        self.decryptor = self.aes_context.decryptor() # Descriptografar
    
    def updateEncryptor(self, plaintext):
        return self.encryptor.update(plaintext)
    
    def finalizeEncryptor(self):
        return self.encryptor.finalize()
    
    def updateDecryptor(self, ciphertext):
        return self.decryptor.update(ciphertext)
    
    def finalizeDecryptor(self):
        return self.decryptor.finalize()

    def calculate_hmac(self, data_chunks): 
        hmac_key = os.urandom(32) # Chave HMAC
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        for chunk in data_chunks:
            h.update(chunk)
        return h.finalize()
    
    def get_keys_concatenated(self):
        return self.encryptor._key + self.decryptor._key  # Concatenar chaves AES e HMAC


def client(email, password):
    
    # Prepara os dados brutos (Plaintext) como JSON
    login_payload = json.dumps({"email": email, "password": password}).encode('utf-8')

    # 2. Gerar chaves aleatórias e IV
    aes_key = os.urandom(32)  # AES-256
    mac_key = os.urandom(32)  # Chave para HMAC
    iv = os.urandom(16)       # Vetor de Inicialização (Nonce)

    # 3. Encriptação Simétrica (AES-CTR)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # No modo CTR, o tamanho da saída é igual à entrada
    ciphertext = encryptor.update(login_payload) + encryptor.finalize()

    # 4. Calcular HMAC do texto cifrado (Encrypt-then-MAC)
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    hmac_signature = h.finalize()

    # 5. Preparar dados para envio (Base64 encoding)
    # Concatenar chaves e IV: [AES_KEY 32b][MAC_KEY 32b][IV 16b]
    session_keys_raw = aes_key + mac_key + iv
    # Encode em Base64
    session_keys_b64 = base64.b64encode(session_keys_raw).decode('utf-8')
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
    if len(sys.argv) != 3:
        print("Usage: python client.py <email> <password>")
        sys.exit(1)
    client(sys.argv[1], sys.argv[2])



