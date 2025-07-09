import socket
import qrcode
import json
import time
from cryptography.fernet import Fernet
import matplotlib.pyplot as plt

# Configuration
FERNET_KEY = Fernet.generate_key()  # Use a consistent key in real scenario
cipher = Fernet(FERNET_KEY)

BANK_IP = "127.0.0.1"
BANK_PORT = 5050
UPI_MACHINE_IP = "127.0.0.1"
UPI_MACHINE_PORT = 6000

# Print server status
print("[UPI Machine] Server is running...")

# Step 1: Accept merchant ID and generate encrypted VMID
merchant_id = input("Enter your Merchant ID: ").strip()
vmid_encrypted = cipher.encrypt(merchant_id.encode()).decode()

print(f"\n[UPI Machine] Generated VMID: {vmid_encrypted}")

# Step 2: Create and show QR code with VMID (DO NOT MODIFY THIS)
qr = qrcode.make(vmid_encrypted)
plt.imshow(qr, cmap='gray')
plt.title("Scan this QR to pay")
plt.axis('off')
plt.show()

# Step 3: Listen for incoming user request
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((UPI_MACHINE_IP, UPI_MACHINE_PORT))
server.listen(5)

print(f"[UPI Machine] Waiting for user to connect on {UPI_MACHINE_IP}:{UPI_MACHINE_PORT}...")

while True:
    conn, addr = server.accept()
    print(f"\n[UPI Machine] Connected to user at {addr}")
    print("[UPI Machine] Waiting to receive data from user...")

    try:
        data = b""
        conn.settimeout(3.0)  # Avoid blocking forever
        try:
            while True:
                packet = conn.recv(4096)
                if not packet:
                    print("[UPI Machine] No more data from user.")
                    break
                data += packet
                if len(packet) < 4096:
                    print("[UPI Machine] Likely end of message.")
                    break
        except socket.timeout:
            print("[UPI Machine] Socket timed out waiting for user data.")
        except Exception as ex:
            print(f"[UPI Machine] Exception while receiving: {ex}")

        if not data:
            print("[UPI Machine] No data received.")
            conn.close()
            continue

        print(f"[UPI Machine] Raw data received from user:\n{data.decode()}\n")
        user_request = json.loads(data.decode())

        if "vmid" not in user_request or "encrypted_data" not in user_request:
            print("[UPI Machine] Missing VMID or encrypted user data in request.")
            conn.send(b"Missing fields.")
            conn.close()
            continue

        print("[UPI Machine] JSON parsed successfully. Keys present:")
        print(f"  - vmid: {user_request.get('vmid')[:50]}...")
        print(f"  - encrypted_data: {user_request.get('encrypted_data')[:50]}...")

        # Extract VMID and encrypted user data
        received_vmid = user_request.get("vmid")
        encrypted_user_data = user_request.get("encrypted_data")

        print(f"\n[UPI Machine] Received VMID: {received_vmid}")
        print(f"[UPI Machine] Encrypted user data: {encrypted_user_data[:60]}...")

        # Step 4: Decrypt VMID to get merchant ID
        try:
            original_merchant_id = cipher.decrypt(received_vmid.encode()).decode()
            print(f"[UPI Machine] Decrypted Merchant ID: {original_merchant_id}")
        except Exception as e:
            print(f"[UPI Machine] Failed to decrypt VMID: {e}")
            conn.send(b"VMID decryption failed.")
            conn.close()
            continue

        # Step 5: Forward to bank
        print(f"\n[UPI Machine] Forwarding to bank =>")
        print(f"  - Merchant ID: {original_merchant_id}")
        print(f"  - Encrypted User Info: {encrypted_user_data[:60]}...")

        bank_payload = {
            "type": "upi_payment",
            "merchant_id": original_merchant_id,
            "encrypted_user_data": encrypted_user_data
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bank_socket:
                print("[UPI Machine] Connecting to bank...")
                bank_socket.connect((BANK_IP, BANK_PORT))
                bank_socket.sendall(json.dumps(bank_payload).encode())
                print("[UPI Machine] Data sent to bank. Waiting for response...")
                bank_response = bank_socket.recv(2048).decode()
                print(f"[UPI Machine] Bank Response: {bank_response}")
                conn.send(bank_response.encode())
        except Exception as e:
            print(f"[UPI Machine] Error connecting to bank: {e}")
            conn.send(b"Bank communication failed.")

    except Exception as ex:
        print(f"[UPI Machine] Error processing request: {ex}")
        conn.send(b"Internal server error.")
    
    conn.close()
