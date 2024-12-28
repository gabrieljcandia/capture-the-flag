import * as fs from "fs";
import { Decrypter } from "./utils/decrypter";

// Constants
const PUBLIC_KEY_PATH = "./external/Public.pub";
const PRIVATE_KEY_PATH = "./external/Private.pem";
const MESSAGE_PATH = "./external/message.txt";

function loadFile(filePath: string): string {
  return fs.readFileSync(filePath, "utf8");
}

function extractMessageParts(message: string): Buffer[] {
  const content = message.split(".").map((part) => Buffer.from(part, "base64"));
  return Array.from(content);
}

function processMessage() {
  const config = {
    SALTED_PREFIX: "Salted__",
    AES_KEY_LENGTH: 32,
    AES_IV_LENGTH: 16,
    PBKDF2_ITERATIONS: 10000,
    PBKDF2_HASH: "sha256",
    ALGORITHM: "aes-256-cbc",
  };

  const decrypter = new Decrypter(config);

  try {
    // Load files
    const publicKey = loadFile(PUBLIC_KEY_PATH);
    const privateKey = loadFile(PRIVATE_KEY_PATH);
    const message = loadFile(MESSAGE_PATH);

    // Split the message into parts
    const [encryptedPassphrase, encryptedPayload, digitalSignature] =
      extractMessageParts(message);

    // Decrypt passphrase
    const decryptedPassphrase = decrypter.decryptPassphrase(
      encryptedPassphrase,
      privateKey
    );

    // Decrypt payload
    const decryptedMessage = decrypter.decryptPayload(
      encryptedPayload,
      decryptedPassphrase
    );
    console.log("Decrypted Message:", decryptedMessage);

    // Verify signature
    const isValid = decrypter.verifySignature(
      encryptedPassphrase,
      digitalSignature,
      publicKey
    );
    console.log(
      isValid
        ? "Passphrase integrity verified: The signature is valid."
        : "Passphrase integrity verification failed: Invalid signature."
    );
  } catch (error) {
    console.error("Error:", error);
  }
}

processMessage();
