#!/usr/bin/env python3
"""
Chiper "Сахар"
KubSTU CTF Shell Client
Protocol: AES-256-CBC | frame = [4B len][16B IV][ciphertext]
Key:      SHA256(password + salt)
"""

import socket
import hashlib
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

########################################################
#  НАСТРОЙКИ 
########################################################
HOST     = "TARGET_HOST"                  # IP сервера
PORT     = 0                              # порт сервера
PASSWORD = b"chocolate"                   # вытащил из из файла pcap 
SALT     = b"a3f7c9b1e2d45608"            # вытащил из из файла pcap 
BANNER   = b">>>ENCRYPTED_CHANNEL_ACTIVE<<<"

########################################################
#  КРИПТОГРАФИЯ
########################################################
KEY = hashlib.sha256(PASSWORD + SALT).digest()

def make_frame(plaintext: bytes) -> bytes:
    """Шифруем и упаковываем в фрейм"""
    iv  = os.urandom(16)
    ct  = AES.new(KEY, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    body = iv + ct
    return len(body).to_bytes(4, 'big') + body

def parse_frame(body: bytes) -> bytes:
    """Распаковываем и расшифровываем фрейм"""
    iv, ct = body[:16], body[16:]
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except Exception:
        pass  # нет паддинга
    return pt

########################################################
#  СЕТЬ
########################################################
def recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Сервер закрыл соединение")
        buf += chunk
    return buf

def recv_frame(sock: socket.socket) -> bytes:
    length = int.from_bytes(recv_exactly(sock, 4), 'big')
    return recv_exactly(sock, length)

def send_cmd(sock: socket.socket, cmd: str):
    sock.sendall(make_frame(cmd.encode('utf-8')))

def recv_response(sock: socket.socket) -> str:
    raw = recv_frame(sock)
    return parse_frame(raw).decode('utf-8', errors='replace')

########################################################
#  HANDSHAKE
########################################################
def wait_for_banner(sock: socket.socket, timeout: float = 10.0) -> str:
    """Ждём баннер перед началом зашифрованного канала"""
    buf = b""
    sock.settimeout(timeout)
    while BANNER not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Соединение закрыто до баннера")
        buf += chunk
    sock.settimeout(None)
    return buf.decode('utf-8', errors='replace').strip()

########################################################
#  MAIN
########################################################
def main():
    print("=" * 47)
    print("  CTF Encrypted Shell Client")
    print(f"[*] AES-256 key: {KEY.hex()}")
    print("=" * 47)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"[*] Подключаемся к {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print("[+] TCP соединение установлено")

            # Handshake: ждём баннер
            banner_text = wait_for_banner(s)
            print(f"[+] Баннер: {banner_text}")
            print("[+] Зашифрованный канал активен!\n")

            # ─── Интерактивный шелл ───────────────────────────
            print("\n[*] Интерактивный режим (Ctrl+C для выхода)")
            print("-" * 47)

            while True:
                try:
                    cmd = input("\033[96m$ \033[0m").strip()
                    if not cmd:
                        continue
                    if cmd.lower() in ("exit", "quit", "q"):
                        print("[*] Выход")
                        break

                    send_cmd(s, cmd)
                    response = recv_response(s)
                    print(response, end="" if response.endswith("\n") else "\n")

                except KeyboardInterrupt:
                    print("\n[*] Прервано пользователем")
                    break

    except ConnectionRefusedError:
        print(f"[!] Соединение отклонено")
        sys.exit(1)
    except ConnectionError as e:
        print(f"[!] Ошибка соединения: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Неожиданная ошибка: {e}")
        raise

if __name__ == "__main__":
    main()
