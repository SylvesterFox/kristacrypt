import eel
import time
import logging
import os
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP


logging.basicConfig(level=logging.INFO)
results = []
eel.init('web')

# Функция отвечает за очиску списка results 
@eel.expose
def clear_results():
    results.clear()
    logging.info("Clear results..")

# Функция генератора ключей RSA
@eel.expose
def generateRSA(folder):
    logging.info('Generate starting..')
    info = []
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open(f"{folder}/private.pem", "wb")
    file_out.write(private_key)
    logging.debug(f'Private:\n {private_key}')
    info.append(private_key)
        
    public_key = key.publickey().export_key()
    file_out = open(f"{folder}/receiver.pem", 'wb')
    file_out.write(public_key)
    logging.debug(f'Public:\n {public_key}')
    logging.info('Generate success..')
    info.append(public_key)
    return f"Public: {public_key}<br> Private: {private_key}<br>{folder}/private.pem -- OK! <br>{folder}/receiver.pem -- OK! <br>ключи созданы."
    

# Главная функция шифратора 
def crypt_file(file, publickey):
    f = open(file, "rb")
    data = f.read()
    f.close()
    file_out = open(str(file) + " .bin", "wb")

    recipient_key = RSA.import_key(open(publickey).read())
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    logging.info(f"Файл: {file} Зашифрован!")
    os.remove(file)
    
# Сканировает файлы и директории, и запускает главную функцию шифратора crypt_file()
@eel.expose
def walk(folder, key):
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        results.append(f"<br>{path}")
        if os.path.isfile(path): 
            crypt_file(path, key)
        else: 
            walk(path, key)
    return results

# Главная функция дешифратора
def decrypt_file(file, privatekey):
        f_in = open(file, "rb")
        file_out = open(str(file[:-4]), "wb")
        private_key = RSA.import_key(open(privatekey).read())

        enc_session_key, nonce, tag, ciphertext = \
        [f_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        file_out.write(data)
        logging.info(f"Файл: {file} расшифрован!")

        f_in.close()
        os.remove(file)

# Сканировает файлы и директории, и запускает главную функцию дешифратора decrypt_file()
@eel.expose
def walk_decrypt(folder, key):
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        results.append(f"<br>{path}")
        if os.path.isfile(path):
            decrypt_file(path, key)
        else: 
            walk_decrypt(path, key)
    return results

logging.info('*sniff* Hello world UwU')
eel.start('index.html', size=(510, 610))
