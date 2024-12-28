# Capture the Flag - Data Decryption Challenge

This project is a data decryption exercise designed to simulate a "capture-the-flag" challenge. It demonstrates the use of encryption, decryption, and digital signature verification using Node.js and cryptographic libraries.

---

## **What This Project Does**

The program:
1. **Decrypts an encrypted passphrase** using an RSA private key.
2. **Decrypts a payload** using the decrypted passphrase, derived using PBKDF2.
3. **Verifies a digital signature** to ensure the integrity of the passphrase using an RSA public key.

This project uses cryptographic standards such as AES-256-CBC for symmetric encryption and RSA for asymmetric encryption. It also ensures secure key derivation using PBKDF2.

---

## **Installation**

### Prerequisites
- Node.js (v18 or later)
- npm (v9 or later)

### Steps
1. Clone this repository:

```bash
git clone git@github.com:gabrieljcandia/capture-the-flag.git
cd capture-the-flag
```
2. Install dependencies:
```
npm install
```
3. Ensure the `.env` file is configured with the necessary variables (details provided below).

## **Usage**

### Running the Program
```
npm start
```

### Environment Variables

Example `.env` File:

```
SALTED_PREFIX=Salted__
AES_KEY_LENGTH=32
AES_IV_LENGTH=16
PBKDF2_ITERATIONS=10000
PBKDF2_HASH=sha256
ALGORITHM=aes-256-cbc

PUBLIC_KEY_PATH=./external/Public.pub
PRIVATE_KEY_PATH=./external/Private.pem
MESSAGE_PATH=./external/message.txt
```

## **Key Files**

The project includes the following key files for demonstration purposes:

- `message.txt`: The encrypted message containing three parts (encrypted passphrase, payload, and digital signature).
- `Private.pem`: The RSA private key used to decrypt the passphrase.
- `Public.pub`: The RSA public key used to verify the digital signature.

### Important Note
For simplicity, the key files have been included in the project. However, in a real-world scenario, sensitive files such as private keys should never be committed to version control. Instead, they should be stored securely and accessed as needed.

