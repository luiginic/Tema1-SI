import socket
import select
from _thread import *
import random

K_prime = b'0123456789ABCDEF'


def generate_key():
    K = '%16x' % random.randrange(16 ** 16)
    print(K)
    return K

def encrypt_key(k):
    enc_key = bytes(k[i] ^ K_prime[i] for i in range(16))
    print(enc_key)
    return enc_key


def decrypt_key(k):
    dec_key = bytes(k[i] ^ K_prime[i] for i in range(16))
    print(dec_key)
    return dec_key

# def encrypt_key(client_k):
#
#     return client_k
#
#

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

IP_addr = '127.0.0.1'
port = 5000

server.bind((IP_addr, port))
server.listen(2)  # se poate pune limita pentru cati clienti sa astepte

list_of_clients = []


def clientthread(conn, addr):
    client_K = generate_key()
    to_send = encrypt_key(client_K.encode())
    conn.send(to_send)  # mai tarziu se trimite cheia pe aici

    while True:
        try:
            msg = conn.recv(1024)
            if msg:
                print("<" + addr[0] + ">" + msg.decode())
                # to_send = "<" + addr[0] + ">" + msg.decode()
                to_send = msg.decode()
                broadcast(to_send.encode(), conn)
            else:
                remove(conn)
        except:
            continue


def broadcast(msg, conn):
    for clients in list_of_clients:
        if clients != conn:
            try:
                clients.send(msg)
            except:
                clients.close()

                remove(clients)


def remove(conn):
    if conn in list_of_clients:
        list_of_clients.remove(conn)


while True:
    connection, address = server.accept()
    list_of_clients.append(connection)
    print("[" + address[0] + " connected]")
    start_new_thread(clientthread, (connection, address))

conncetion.close()
server.close()
