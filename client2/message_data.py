import struct

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 2345


MSG_HEADER_SIZE = 22


"""
Message Types
"""
MT_CLIENT_INFO = 0  # client information
MT_SECURE_DIGIT = 1  # secure one digit
MT_AUTH_REQ = 2  # authentication requrest
MT_REGISTERED = 3  # register success
MT_CLIENT_LIST = 4  # client list
MT_NOTIFY_NEW = 5  # notify new client
MT_EXCHANGE_KEY = 6  # session key exchange

MT_MESSAGE = 7  # new message
MT_ACK_SENT = 8  # message sent to server
MT_ACK_PENDING = 9  # message is pending
MT_ACK_DISCARD = 10  # message discard
MT_ACK_DELIVER = 11  # message delivered to client


class MessageHeader:
    def __init__(self):
        self.message_type = 0
        self.sender_phone = ""
        self.recipient_phone = ""
        self.payload_len = 0

    # create bytes buffer from message header
    def pack_to_bytes(self):
        data_buf = struct.pack("<H", self.message_type)
        data_buf += struct.pack("<8s", self.sender_phone.encode("utf-8").ljust(8, b'\x00'))
        data_buf += struct.pack("<8s", self.recipient_phone.encode("utf-8").ljust(8, b'\x00'))
        data_buf += struct.pack("<I", self.payload_len)
        return data_buf

    # create message header from bytes
    def build_from_bytes(self, data_buf):
        self.message_type = struct.unpack("<H", data_buf[0:2])[0]
        self.sender_phone = data_buf[2:10].decode("utf-8").rstrip('\x00')
        self.recipient_phone = data_buf[10:18].decode("utf-8").rstrip('\x00')
        self.payload_len = struct.unpack("<I", data_buf[18:22])[0]


# Send Packet
def send_data(sock, packet_type, sender, recipient, payload):
    msg_header = MessageHeader()
    msg_header.message_type = packet_type
    msg_header.recipient_phone = recipient
    msg_header.sender_phone = sender
    msg_header.payload_len = len(payload)
    sock.send(msg_header.pack_to_bytes() + payload)


# Receive packet
def receive_data(sock):
    buf = sock.recv(MSG_HEADER_SIZE)
    msg_header = MessageHeader()
    msg_header.build_from_bytes(buf)
    payload = b''
    if msg_header.payload_len != 0:
        payload = sock.recv(msg_header.payload_len)
    return msg_header, payload
