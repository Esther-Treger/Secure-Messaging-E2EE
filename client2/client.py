import socket
import sys
import threading

from message_data import *
from utilities import *

PHONE_FILE = "phone.txt"
PUBKEY_FILE = "pubkey"
PRVKEY_FILE = 'prvkey'
SERVER_PUBKEY_FILE = "server_pubkey"
CLIENTS_FILE = "clients"

class Client:

    def __init__(self, my_phone, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.my_phone = my_phone
        self.public_key = b''
        self.private_key = b''
        self.server_key = b''
        # {phone:{'public_key':public_key,'session_key':session_key}}
        self.other_clients = load_json_file(CLIENTS_FILE)

        # Load client's RSA key pair
        self.public_key = load_rsa_key(PUBKEY_FILE)
        self.private_key = load_rsa_key(PRVKEY_FILE)
        if self.public_key == b'' or self.private_key == b'':
            self.public_key, self.private_key = create_rsa_key_pair()
            save_rsa_key(PUBKEY_FILE, self.public_key)
            save_rsa_key(PRVKEY_FILE, self.private_key)

        # Load server's public key
        self.server_key = load_rsa_key("server_pubkey")
        if self.server_key == b'':
            print("[Error]: Server key file not found.")
            exit(0)

        # Connect to server
        self.socket.connect((host, port))

        # Register to server
        if not self.register_to_server():
            print("[Error]: Registering to server failed.")
            exit(0)

        # Start receiving thread
        self.receive_thread = threading.Thread(target=self.handle_messages, daemon=True)
        self.receive_thread.start()

    # Registration
    def register_to_server(self):
        # 1. Send client information to server
        print("*** Sending client information to server ...", end=' ')
        payload = json.dumps({
            'client_id': self.my_phone,
            'public_key': self.public_key.decode()
        }).encode()
        send_data(self.socket, MT_CLIENT_INFO, self.my_phone, '', payload)
        print("Success")

        # 2. Receive authentication code from server by secure channel
        print("*** Receiving authentication code from server by secure channel ...", end=' ')
        msg_header, payload = receive_data(self.socket)
        if msg_header.message_type != MT_SECURE_DIGIT:
            print("Fail")
            return False
        print("Success")
        json_data = json.loads(payload.decode())

        # 3. Send encrypted authentication code to server
        print("*** Sending encrypted authentication code to server ...", end=' ')
        digit_data = json.dumps({
            'digit': json_data['digit']
        }).encode()
        payload = rsa_encrypt(digit_data, self.server_key).encode()
        send_data(self.socket, MT_AUTH_REQ, self.my_phone, '', payload)
        print("Success")

        # 4. Receive register confirm message from server
        print("*** Receiving register result from server ...", end=' ')
        msg_header, payload = receive_data(self.socket)
        if msg_header.message_type == MT_REGISTERED:
            print("Success")
            return True
        else:
            print("Fail")
            return False

    # Received data processing
    def handle_messages(self):
        while True:
            try:
                msg_header, payload = receive_data(self.socket)
                json_data = {}
                if msg_header.payload_len != 0:
                    json_data = json.loads(payload.decode())

                if msg_header.message_type == MT_CLIENT_LIST:
                    self.handle_client_list(json_data['clients'])
                elif msg_header.message_type == MT_NOTIFY_NEW:
                    self.handle_new_client(json_data)
                elif msg_header.message_type == MT_EXCHANGE_KEY:
                    self.receive_session_key(msg_header, json_data)
                elif msg_header.message_type == MT_MESSAGE:
                    self.handle_message(msg_header, json_data)
                elif msg_header.message_type == MT_ACK_SENT:
                    print(f"*** Message to {msg_header.recipient_phone} was sent.")
                elif msg_header.message_type == MT_ACK_DELIVER:
                    print(f"*** Message to {msg_header.recipient_phone} was delivered.")
                elif msg_header.message_type == MT_ACK_PENDING:
                    print(f"*** Message to {msg_header.recipient_phone} was pended.")
                elif msg_header.message_type == MT_ACK_DISCARD:
                    print(f"*** Message to {msg_header.recipient_phone} was discarded.")
                else:
                    print(f"[Error]: Unknown message")

            except Exception as e:
                print(f"[Error]: Receiving message - {e}")
                break

    # Save a client list into repository
    def handle_client_list(self, clients):
        print(f"*** Receiving client list from server ...", end=' ')
        for key, value in clients.items():
            if key not in self.other_clients:
                self.other_clients[key] = {}
            self.other_clients[key]['public_key'] = value['public_key']
        print("Success")
        save_json_file(self.other_clients, CLIENTS_FILE)

    # Save a new client and session key processing
    def handle_new_client(self, data):
        client_phone = data['client_id']
        client_pubkey = data['public_key']
        print(f"*** Received client information on {client_phone}")
        self.other_clients[client_phone] = {'public_key': client_pubkey}
        save_json_file(self.other_clients, CLIENTS_FILE)
        self.exchange_session_key(client_phone, client_pubkey)

    # Generate a session key and send to new client
    def exchange_session_key(self, client_phone, client_pubkey):
        print(f"*** Exchanging session key with {client_phone} ...", end=' ')
        # Create session_key
        master_key = os.urandom(32)  # Random master key
        session_key = create_session_key(master_key)

        # Store session key
        self.other_clients[client_phone]['session_key'] = session_key.hex()
        save_json_file(self.other_clients, CLIENTS_FILE)

        encrypted_key = rsa_encrypt(session_key, client_pubkey)

        # Send encrypted session key
        payload = json.dumps({
            'encrypted_key': encrypted_key
        }).encode()
        send_data(self.socket, MT_EXCHANGE_KEY, self.my_phone, client_phone, payload)
        print("Success")

    # Process received session key, that is saved into repository
    def receive_session_key(self, msg_header, data):
        try:
            sender_phone = msg_header.sender_phone
            session_key = rsa_decrypt(data['encrypted_key'], self.private_key)
            print(f"*** Received session key from {sender_phone}")

            self.other_clients[sender_phone]['session_key'] = session_key.hex()
            save_json_file(self.other_clients, CLIENTS_FILE)

        except Exception as e:
            print(f"[Error]: Receiving session key: {e}")

    # Process received message, that is decrypted with a session key
    def handle_message(self, msg_header, data):
        try:
            sender_phone = msg_header.sender_phone
            session_hex_key = self.other_clients[sender_phone]['session_key']
            print(f"*** Message from {sender_phone}, decrypting and verifying ...", end=' ')
            decrypted_message = aes_decrypt(data['content'], session_hex_key, data['nonce'])
            # verify HMAC
            is_valid = verify_hmac(session_hex_key, decrypted_message, data['mac'])
            if is_valid:
                print("Success")
                print(f"> From {sender_phone}: \"{decrypted_message}\"")
                send_data(self.socket, MT_ACK_DELIVER, sender_phone, self.my_phone, b'')
            else:
                print("Fail")
        except Exception as e:
            print("Fail")
            print(f"[Error]: Decrypting message: {e}")

    # Send a message, that is encrypted with a session key
    def send_message(self, recipient_phone, message):
        if recipient_phone == self.my_phone:
            print(f">From {self.my_phone}: \"{message}\"")
            return
        if recipient_phone not in self.other_clients \
                or self.other_clients[recipient_phone]['session_key'] == b'':
            print("[Error]: Session key not exchanged with this user")
            return
        try:
            session_hex_key = self.other_clients[recipient_phone]['session_key']
            encrypted_content, nonce = aes_encrypt(message, session_hex_key)
            mac = create_hmac(session_hex_key, message)
            payload = json.dumps({
                'content': encrypted_content,
                'nonce': nonce,
                'mac': mac
            }).encode()
            send_data(self.socket,
                      MT_MESSAGE,
                      self.my_phone,
                      recipient_phone,
                      payload)
        except Exception as e:
            print(f"[Error]: Sending message: {e}")

    def start(self):
        print(f"*** Register success with phone number: {self.my_phone}.")
        while True:
            try:
                user_input = input()
                recipient_phone, message = user_input.split(' ', 1)
                recipient_phone = recipient_phone.strip()
                self.send_message(recipient_phone, message)
            except Exception as e:
                print(f"Error: {e}")


if __name__ == "__main__":
    phone = ''
    try:
        with open(PHONE_FILE, 'r', encoding='utf-8') as f:
            phone = f.readline()
    except Exception as e:
        print("[Error]: Cannot get phone number.")
        sys.exit(0)
    print("[Send Message]: <phone number> <message>")
    client = Client(phone, SERVER_ADDRESS, SERVER_PORT)
    client.start()
