import * as fs from "fs";
import * as crypto from "crypto";

// Constants
const PUBLIK_KEY_PATH = "./external/Public.pub";
const PRIVATE_KEY_PATH = "./external/Private.pem";
const MESSAGE_PATH = "./external/message.txt";
const SALTED_PREFIX = "Salted__"; // Prefix for OpenSSL-encrypted files
const AES_KEY_LENGTH = 32; // AES-256 key size in bytes
const AES_IV_LENGTH = 16; // AES Initialization Vector size in bytes
const PBKDF2_ITERATIONS = 10000; // Number of iterations for PBKDF2
const PBKDF2_HASH = "sha256"; // Hashing algorithm for PBKDF2

// Load files
const publicKey = fs.readFileSync(PUBLIK_KEY_PATH, "utf8");
const privateKey: string = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");
const message: string = fs.readFileSync(MESSAGE_PATH, "utf8");

// Split message into its components: encrypted passphrase, encrypted payload, and digital signature
const [encryptedPassphrase, encryptedPayload, digitalSignature] =
  message.split(".");

/**
 * Decrypts the encrypted passphrase using the provided RSA private key.
 * @param encryptedPassphrase - The Base64 encoded encrypted passphrase.
 * @param privateKey - The RSA private key used for decryption.
 * @returns The decrypted passphrase as a Buffer.
 */
function decryptPassphrase(
  encryptedPassphrase: Buffer,
  privateKey: string
): Buffer {
  // Decrypt the passphrase using the private key with PKCS#1 padding
  return crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    encryptedPassphrase
  );
}

/**
 * Decrypts the payload (part 2) using the decrypted passphrase.
 * @param payload - The binary payload containing the "Salted__" prefix, salt, and encrypted data.
 * @param passphrase - The passphrase used to derive the encryption key and IV.
 * @returns The decrypted payload as a UTF-8 string.
 */
function decryptPayload(payload: Buffer, passphrase: Buffer): string {
  try {
    // Verify the payload starts with the "Salted__" prefix
    if (payload.slice(0, 8).toString() !== SALTED_PREFIX) {
      throw new Error(
        "Part 2 file does not have the expected Salted__ prefix."
      );
    }

    // Extract the salt (next 8 bytes after the prefix)
    const salt = payload.slice(8, 16);

    // Extract the encrypted data (everything after the salt)
    const encryptedData = payload.slice(16);

    // Derive the encryption key and IV using PBKDF2
    const derivedKey = crypto.pbkdf2Sync(
      passphrase,
      salt,
      PBKDF2_ITERATIONS,
      AES_KEY_LENGTH + AES_IV_LENGTH,
      PBKDF2_HASH
    );
    const key = derivedKey.slice(0, AES_KEY_LENGTH);
    const iv = derivedKey.slice(AES_KEY_LENGTH, AES_KEY_LENGTH + AES_IV_LENGTH);

    // Decrypt the encrypted data using AES-256-CBC
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    // Return the decrypted data as a UTF-8 string
    return decrypted.toString("utf8");
  } catch (error) {
    console.error("Error during decryption:", (error as Error).message);
    throw error;
  }
}

/**
 * Verifies the digital signature of the passphrase using the public key.
 * @param passphrase - The passphrase as binary data.
 * @param signature - The digital signature as binary data.
 * @param publicKey - The public key used to verify the signature.
 * @returns `true` if the signature is valid, `false` otherwise.
 */
function verifySignature(
  passphrase: Buffer,
  signature: Buffer,
  publicKey: string
): boolean {
  try {
    // Create a verifier object using the same hash algorithm used during signing
    const verifier = crypto.createVerify("sha256");

    // Update the verifier with the data to be verified (the passphrase)
    verifier.update(passphrase);

    // Finalize the verification process
    verifier.end();

    // Verify the signature using the public key
    // Returns true if the signature matches the passphrase, false otherwise
    return verifier.verify(publicKey, signature);
  } catch (error) {
    console.error(
      "Error during signature verification:",
      (error as Error).message
    );
    return false;
  }
}

try {
  const passphrase = Buffer.from(encryptedPassphrase, "base64");
  const decryptedPassphrase = decryptPassphrase(passphrase, privateKey);

  const decryptedMessage = decryptPayload(
    Buffer.from(encryptedPayload, "base64"),
    decryptedPassphrase
  );

  console.log("Decrypted Message:", decryptedMessage);

  const signature = Buffer.from(digitalSignature, "base64");
  const isValid = verifySignature(passphrase, signature, publicKey);
  if (isValid) {
    console.log("Passphrase integrity verified: The signature is valid.");
  } else {
    console.error(
      "Passphrase integrity verification failed: Invalid signature."
    );
  }
} catch (error) {
  console.error("Error:", error);
}
