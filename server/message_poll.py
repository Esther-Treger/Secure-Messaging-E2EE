from typing import Dict, List


class MessagePoll:
    def __init__(self):
        self.clients: Dict[str, dict] = {}

    def add_client(self, client_phone):
        if client_phone not in self.clients:
            self.clients[client_phone] = {'pending_messages': []}

    def add_pending_message(self, recipient_phone, sender_phone,
                            message_type: int,
                            content: bytes) -> bool:
        if recipient_phone not in self.clients:
            return False

        pending_messages = self.clients[recipient_phone]['pending_messages']

        if len(pending_messages) >= 2:
            return False

        pending_messages.append({'packet_type': message_type, 'sender_id': sender_phone, 'content': content})

        return True

    def get_pending_messages(self, client_phone: str) -> List[dict]:
        if client_phone not in self.clients:
            return []
        return self.clients[client_phone]['pending_messages']

    def clear_messages(self, client_phone: str) -> bool:
        if client_phone not in self.clients:
            return False
        self.clients[client_phone]['pending_messages'] = []
        return True
