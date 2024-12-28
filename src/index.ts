import * as fs from "fs";
import * as dotenv from "dotenv";
import { Decrypter, DecrypterConfig } from "./utils/decrypter";

function loadFile(filePath: string): string {
  return fs.readFileSync(filePath, "utf8");
}

function extractMessageParts(message: string): Buffer[] {
  const content = message.split(".").map((part) => Buffer.from(part, "base64"));
  return Array.from(content);
}

function processMessage() {
  // Load environment variables
  dotenv.config();

  const config: DecrypterConfig = {
    SALTED_PREFIX: process.env.SALTED_PREFIX,
    AES_KEY_LENGTH: parseInt(process.env.AES_KEY_LENGTH),
    AES_IV_LENGTH: parseInt(process.env.AES_IV_LENGTH),
    PBKDF2_ITERATIONS: parseInt(process.env.PBKDF2_ITERATIONS),
    PBKDF2_HASH: process.env.PBKDF2_HASH,
    ALGORITHM: process.env.ALGORITHM,
  };

  const decrypter = new Decrypter(config);

  try {
    // Load files
    const publicKey = loadFile(process.env.PUBLIC_KEY_PATH);
    const privateKey = loadFile(process.env.PRIVATE_KEY_PATH);
    const message = loadFile(process.env.MESSAGE_PATH);

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
