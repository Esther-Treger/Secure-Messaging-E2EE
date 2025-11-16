🔐 Secure Messaging System (E2EE) — Python

A fully implemented end-to-end encrypted messaging system written in Python, featuring secure key exchange, RSA authentication, AES-256-GCM encryption, and a multi-client communication flow.
Developed as part of an advanced security programming assignment at the Open University.

📌 Overview

This project implements a secure chat system inspired by modern messaging applications.
The design focuses on confidentiality, integrity, authentication, and reliable message delivery.

The system supports:

Multi-client communication

End-to-end encryption

Secure registration & authentication

Session key distribution

Asynchronous message polling

Message queueing for offline clients

🧠 Architecture

🖥 Server

The central server handles:

Client registration

Public key distribution

Forwarding encrypted messages

Storing undelivered messages

RSA-based authentication

It maintains:

A phone-number–to–public-key registry

A pending-messages queue

A routing mechanism for online clients

📱 Client

Each client:

Generates an RSA key pair (or loads an existing one)

Registers securely with the server

Exchanges session keys with peers

Sends and receives AES-encrypted messages

Verifies integrity using GCM tags

Stores local session keys for secure communication

🔐 Cryptography

✔ RSA-2048

Used for authentication + encrypting session keys.

✔ AES-256-GCM

Used for message confidentiality + integrity.

✔ HKDF

Derives symmetric session keys from shared secrets.

✔ Challenge–Response

Clients prove ownership of their private key to the server.

📦 Project Structure

server.py                – Main server logic
client.py                – Main client logic
utils/
    rsa_utils.py         – RSA load/generate/encrypt/decrypt
    aes_utils.py         – AES-GCM encryption/decryption
    key_derivation.py    – HKDF session key generator
message_data/            – Local encrypted messages
message_poll/            – Pending message polling
requirements.txt
README.md

▶️ Running the System

1️⃣ Install dependencies
pip install -r requirements.txt

2️⃣ Start the server
python server.py


This will generate the server RSA key pair (or load an existing one).

3️⃣ Start a client

Create a phone.txt containing the client’s phone number.

Then run:

python client.py


You may open multiple clients to simulate conversations.

🧪 Features Demonstrated

Real E2EE message flow

Authentication using RSA challenge-response

Secure key exchange

Offline message delivery

Multi-threaded server

Structured OOP-style utilities

Clear separation of cryptography and networking layers

📚 Notes

This project demonstrates secure system design, cryptographic correctness, and reliable client-server architecture.
It is intended for educational and portfolio purposes.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Focus-Security%20Engineering-8A2BE2)
![Encryption](https://img.shields.io/badge/Encryption-AES256%20%7C%20RSA2048-success)
