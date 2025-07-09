import socket
import json
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes

# Configuration
UPI_MACHINE_IP = "127.0.0.1"
UPI_MACHINE_PORT = 6000
BANK_IP = "127.0.0.1"
BANK_PORT = 5050

PUBLIC_KEY_PEM = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj/unz6KcHEkIpikcCMZ8
66I+VeWeC2mY1BBpp2hPt3nO4icOJ8D6SAWCjKNuLpz1MTXGf3KojKUob0+rxymw
t8SGD/SVNcNZxGoxN0j74MpGDJvxvEXNC7RB0jqPAy40CmQwm0MZwQNUd2MBrMMo
u8FAGGgHcnKVV0aPvpiUd0WehimzW+fwb9N7LNqfP7jFaDCu7fGKTXuTiI9ooXp3
CtD4EhC3rlV8lWlv5A6e9DgHwcQgopawIBA3SzVVkHsOdRx49dliQYBrVZeD0Orz
t+Sz2UlLYRn8PPGHrwLO+O5h6Xlu3OpVJ8lCCz2IV/6tHBI3/lk8VFn9AULXeUuh
kQIDAQAB
-----END PUBLIC KEY-----
"""

# Load it once and use
UPI_PUBLIC_KEY = serialization.load_pem_public_key(PUBLIC_KEY_PEM)

#Register with  Bank

def register_user():
    print("Registering with Bank")
    name = input("Enter your name: ").strip()
    ifsc = input("Enter IFSC code: ").strip()
    mobile = input("Enter your mobile number: ").strip()
    password = input("Set your login password: ").strip()
    amount = input("Enter initial balance: ").strip()
    pin = input("Set 4-digit UPI PIN: ").strip()

    request_data = {
        "type": "register",
        "name": name,
        "ifsc": ifsc,
        "mobile": mobile,
        "password": password,
        "amount": amount,
        "pin": pin,
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((BANK_IP, BANK_PORT))
            s.sendall(json.dumps(request_data).encode())
            response = s.recv(1024).decode()
            print("Bank Response:", response)
    except Exception as e:
        print("Error connecting to bank server:", e)

#Initiate UPI Payment

def initiate_payment():
    print("Initiate UPI Payment")
    vmid = input("Enter VMID (Vendor MMID): ").strip()
    mmid = input("Enter your MMID: ").strip()
    amount = input("Enter amount to transfer: ").strip()
    pin = input("Enter your UPI PIN: ").strip()
    
    sensitive = f"{mmid}:{amount}:{pin}".encode()
    print("[User] Preparing to encrypt sensitive data...")

    public_key = UPI_PUBLIC_KEY
    encrypted = public_key.encrypt(
        sensitive,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("[User] Encryption done.") 
    
    encrypted_hex = encrypted.hex()

    request_data = {
        "type": "user_payment",
        "vmid": vmid,              # plaintext
        "encrypted_data": encrypted_hex  # hex
    }
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((UPI_MACHINE_IP, UPI_MACHINE_PORT))
            s.sendall(json.dumps(request_data).encode())
            response = s.recv(1024)
            print("Response from UPI Machine:", response.decode())
    except Exception as e:
        print("Error connecting to UPI machine:", e)


def main():
    print("Welcome to Custom UPI Client")
    print("1. Register with Bank")
    print("2. Initiate Payment")
    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == "1":
        register_user()
    elif choice == "2":
        initiate_payment()
    else:
        print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
