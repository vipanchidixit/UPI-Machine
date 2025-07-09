import socket
import json
import threading
import hashlib

# Config
BANK_IP = "127.0.0.1"
BANK_PORT = 5050

# Mock DBs
users_db = {}
upi_pins = {}

def handle_client(conn, addr):
    print(f"[BANK] Connected to {addr}")
    data = conn.recv(4096).decode()

    if not data:
        print("[BANK] No data received.")
        conn.close()
        return

    try:
        request = json.loads(data)
        req_type = request.get("type")

        if req_type == "register":
            name = request.get("name")
            ifsc = request.get("ifsc")
            mobile = request.get("mobile")
            password = request.get("password")
            balance = float(request.get("amount", 0))
            pin = request.get("pin")

            user_key = f"{name}_{mobile}_{ifsc}"
            users_db[user_key] = {
                "name": name,
                "ifsc": ifsc,
                "mobile": mobile,
                "password_hash": hashlib.sha256(password.encode()).hexdigest(),
                "balance": balance
            }
            upi_pins[mobile] = hashlib.sha256(pin.encode()).hexdigest()

            print(f"[BANK] Registered user: {user_key}")
            conn.send(b"Registration successful.")

        elif req_type == "upi_payment":
            merchant_id = request.get("merchant_id")
            encrypted_data = request.get("encrypted_user_data")

            print(f"[BANK] Received UPI payment request for Merchant: {merchant_id}")
            print(f"[BANK] Encrypted User Info: {encrypted_data[:60]}...")

            # In real scenario, decryption happens here using bank's private key.
            # For now, we simulate success without decrypting.
            conn.send(b"Payment successful and forwarded to merchant.")

        else:
            conn.send(b"Invalid request type.")

    except Exception as e:
        print("[BANK] Error processing request:", e)
        conn.send(b"Internal server error.")

    conn.close()

def start_server():
    print(f"[BANK] Server starting on {BANK_IP}:{BANK_PORT}...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((BANK_IP, BANK_PORT))
    server.listen(5)

    while True:
        conn, addr = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()

if __name__ == "__main__":
    start_server()
