import random
import socket
import threading

from message_data import *
from message_poll import *
from utilities import *


class Server:

    def __init__(self, host, port):
        self.clients = {}  # {client_id: {'socket': socket, 'public_key': key}}
        self.pending_message_manager = MessagePoll()
        # load private key, if failed, create rsa key pair
        self.private_key = load_rsa_key("server_prvkey")
        if self.private_key == b'':
            self.public_key, self.private_key = create_rsa_key_pair()
            save_rsa_key("server_pubkey", self.public_key)
            save_rsa_key("server_prvkey", self.private_key)

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(5)

        print(f"Server started on {host}:{port}")

    def start(self):
        while True:
            client_socket, address = self.server.accept()
            print(f"\n*** New client connected : {address}")
            thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            thread.daemon = True
            thread.start()

    # Send digit by secure channel
    def send_by_secure_channel(self, digit, client_socket, client_phone):
        print(f"*** Sending authentication code to {client_phone} by secure channel ...", end=' ')
        digit_data = json.dumps({'digit': digit}).encode()
        send_data(client_socket,
                  MT_SECURE_DIGIT,
                  '',
                  client_phone,
                  digit_data)
        print("Success")

    # send deliver acknowledgement
    def send_deliver_acknowledge(self, msg_header):
        sender_phone = msg_header.sender_phone
        recipient_phone = msg_header.recipient_phone
        sock = self.clients[sender_phone]['socket']
        print(f"*** Sending deliver ack to {sender_phone} ...", end=' ')
        send_data(sock,
                  MT_ACK_DELIVER,
                  sender_phone,
                  recipient_phone,
                  b'')
        print("Success")

    # Relay the received data to other clients
    def relay_message(self, msg_header, message_data):
        recipient_phone = msg_header.recipient_phone
        sender_phone = msg_header.sender_phone
        if recipient_phone in self.clients:
            try:
                sock = self.clients[recipient_phone]['socket']
                print(f"*** Relaying message to {recipient_phone} ...", end=' ')
                send_data(sock,
                          msg_header.message_type,
                          msg_header.sender_phone,
                          msg_header.recipient_phone,
                          message_data)
                print("Success")

                if msg_header.message_type == MT_MESSAGE:
                    # send ack message
                    print(f"*** Sending message ack to {recipient_phone} ...", end=' ')
                    sock = self.clients[sender_phone]['socket']
                    send_data(sock,
                              MT_ACK_SENT,
                              msg_header.sender_phone,
                              msg_header.recipient_phone,
                              b'')
                    print("Success")
            except:
                print(f"[Error]: Sending to {recipient_phone}")
        else:
            if msg_header.message_type == MT_MESSAGE:
                if self.pending_message_manager.add_pending_message(recipient_phone,
                                                                    msg_header.sender_phone,
                                                                    msg_header.message_type,
                                                                    message_data):
                    # send ack message
                    print(f"*** Sending message pending ack to {recipient_phone} ...", end=' ')
                    sock = self.clients[sender_phone]['socket']
                    send_data(sock,
                              MT_ACK_PENDING,
                              msg_header.sender_phone,
                              msg_header.recipient_phone,
                              b'')
                    print("Success")
                else:
                    # send ack message
                    sock = self.clients[sender_phone]['socket']
                    print(f"*** Sending message discard ack to {recipient_phone} ...", end=' ')
                    send_data(sock,
                              MT_ACK_DISCARD,
                              msg_header.sender_phone,
                              msg_header.recipient_phone,
                              b'')
                    print("Success")

    # Notify a new client information to other clients
    def notify_new_client(self, new_client_phone, public_key):
        message_data = json.dumps({'client_id': new_client_phone, 'public_key': public_key}).encode()
        for client_phone, client_data in self.clients.items():
            if client_phone != new_client_phone:
                print(f"*** Notifying new client to {client_phone} ...", end=' ')
                try:
                    sock = self.clients[client_phone]['socket']
                    send_data(sock, MT_NOTIFY_NEW, '', client_phone, message_data)
                    print("Success")
                except:
                    print("Fail")
                    continue

    # Remove a client from a list
    def remove_client(self, client_phone):
        if client_phone in self.clients:
            print(f"*** Removing client {client_phone} ...", end=' ')
            self.clients[client_phone]['socket'].close()
            del self.clients[client_phone]
            print("Success")

    # Client socket processing
    def handle_client(self, client_socket):
        client_phone = ''
        try:
            # 1. Receive client information
            print(f"*** Registering new client ...")
            print(f"*** Receiving client information ...", end=' ')
            msg_header, payload = receive_data(client_socket)
            json_data = json.loads(payload.decode())
            client_phone = json_data['client_id']
            client_public_key = json_data['public_key']
            print(f"Success")

            # 2. Generate authentication code and send it by secure channel
            digit = random.randint(0, 9)
            self.send_by_secure_channel(digit, client_socket, client_phone)

            # 3. Receive authentication code and check
            print(f"*** Receiving authentication code from {client_phone} ... ", end=' ')
            msg_header, payload = receive_data(client_socket)
            print("Success")
            print(f"*** Checking authentication code from {client_phone} ...", end=' ')
            if msg_header.message_type != MT_AUTH_REQ:
                print("Fail")
                return
            digit_data = json.loads(rsa_decrypt(payload, self.private_key).decode())
            if digit_data['digit'] != digit:
                print("Fail")
                return
            print("Success")

            # 4. Send register success message
            print(f"*** Sending register success message to {client_phone} ...", end=' ')
            send_data(client_socket, MT_REGISTERED, '', client_phone, b'')
            print(f"Success")

            # Save client information
            self.clients[client_phone] = {'socket': client_socket, 'public_key': client_public_key}

            # 5. Send current client list to new client
            print(f"*** Sending client list to {client_phone} ...", end=' ')
            client_list = {
                cid: {'public_key': data['public_key']}
                for cid, data in self.clients.items()
                if cid != client_phone
            }
            list_data = json.dumps({
                'clients': client_list
            }).encode()
            send_data(client_socket, MT_CLIENT_LIST, '', client_phone, list_data)
            print(f"Success")

            # 6. Send pending messages
            self.pending_message_manager.add_client(client_phone)
            pending_messages = self.pending_message_manager.get_pending_messages(client_phone)
            if len(pending_messages) != 0:
                print(f"*** Sending pending messages to {client_phone} ...", end=' ')
                for item in pending_messages:
                    send_data(client_socket, item['packet_type'], item['sender_id'], client_phone, item['content'])
                self.pending_message_manager.clear_messages(client_phone)
                print("Success")

            # 7. Notify new client connection to others
            self.notify_new_client(client_phone, client_public_key)

            # Handle messages
            while True:
                try:
                    msg_header, payload = receive_data(client_socket)
                    if msg_header.message_type == MT_MESSAGE \
                            or msg_header.message_type == MT_EXCHANGE_KEY:
                        self.relay_message(msg_header, payload)
                    if msg_header.message_type == MT_ACK_DELIVER:
                        self.send_deliver_acknowledge(msg_header)
                except:
                    break

        except Exception as e:
            print(f"[Error]: Handling client - {e}")
        finally:
            self.remove_client(client_phone)


if __name__ == "__main__":
    server = Server(SERVER_ADDRESS, SERVER_PORT)
    server.start()
