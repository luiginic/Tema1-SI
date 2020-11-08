import select
import socket
import sys

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

K_prime = b'0123456789ABCDEF'


def encrypt_key(k):
    enc_key = bytes(k[i] ^ K_prime[i] for i in range(16))
    # print(enc_key)
    return enc_key


def decrypt_key(k):
    dec_key = bytes(k[i] ^ K_prime[i] for i in range(16))
    # print(dec_key)
    return dec_key



def encrypt_text(txt, k):
    pos = 0
    cipher_text_blocks = []
    iv = get_random_bytes(16)
    IV = iv
    cipher = AES.new(k, AES.MODE_ECB)
    if len(txt) % 16 != 0:
        txt += b"1"
    while len(txt) % 16 != 0:
        txt += b"0"
    while pos + 16 <= len(txt):
        to_xor = cipher.encrypt(iv)
        next_index = pos + 16
        to_enc = txt[pos:next_index]
        cipher_text = bytes([to_xor[i] ^ to_enc[i] for i in range(16)])
        cipher_text_blocks.append(cipher_text)
        pos += 16
        iv = to_xor
    return (IV, cipher_text_blocks)


def decrypt_text(cipher_text_blocks, k, iv):
    txt = b""
    cipher = AES.new(k, AES.MODE_ECB)
    for block in cipher_text_blocks:
        to_xor = cipher.encrypt(iv)
        txt += bytes([to_xor[i] ^ block[i] for i in range(16)])
        iv = to_xor
    while txt[-1] == 48:
        txt = txt[0:-1]
    if txt[-1] == 49:
        txt = txt[0:-1]
    return txt


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

IP_addr = '127.0.0.1'
port = 5000

server.connect((IP_addr, port))
K = server.recv(1024)
K = decrypt_key(K)
# print(K.decode())

while True:
    sockets_list = [sys.stdin, server]

    read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])

    for sockets in read_sockets:
        if sockets == server:
            msg = sockets.recv(1024)
            message = msg.decode()
            message = eval(message)
            dec_key = message[0]
            dec_key = decrypt_key(dec_key)
            iv = message[1]
            enc_txt = message[2]
            # print('key is:', dec_key)
            # print('iv:', iv)
            # print('message is:', enc_txt)
            text = decrypt_text(enc_txt, dec_key, iv)
            print(text)
        else:
            text = input().encode()
            to_send = []
            iv, enc_text = encrypt_text(text, K)
            print("Sending..")
            # print("Text:" + str(text))
            # print("iv:", iv)
            # print("enc_text:", enc_text)

            to_send.append(encrypt_key(K))
            to_send.append(iv)
            to_send.append(enc_text)
            server.send(str(to_send).encode())
            print("Message sent!")
            sys.stdout.flush()
server.close()
