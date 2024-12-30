import * as crypto from "crypto";

export interface DecrypterConfig {
  SALTED_PREFIX: string;
  AES_KEY_LENGTH: number;
  AES_IV_LENGTH: number;
  PBKDF2_ITERATIONS: number;
  PBKDF2_HASH: string;
  ALGORITHM: string;
}

export class Decrypter {
  private SALTED_PREFIX: string;
  private AES_KEY_LENGTH: number;
  private AES_IV_LENGTH: number;
  private PBKDF2_ITERATIONS: number;
  private PBKDF2_HASH: string;
  private ALGORITHM: string;

  constructor(config: DecrypterConfig) {
    this.SALTED_PREFIX = config.SALTED_PREFIX;
    this.AES_KEY_LENGTH = config.AES_KEY_LENGTH;
    this.AES_IV_LENGTH = config.AES_IV_LENGTH;
    this.PBKDF2_ITERATIONS = config.PBKDF2_ITERATIONS;
    this.PBKDF2_HASH = config.PBKDF2_HASH;
    this.ALGORITHM = config.ALGORITHM;
  }

  /**
   * Decrypts the encrypted passphrase using the provided RSA private key.
   * @param encryptedPassphrase - The Base64 encoded encrypted passphrase.
   * @param privateKey - The RSA private key used for decryption.
   * @returns The decrypted passphrase as a Buffer.
   */
  public decryptPassphrase(
    encryptedPassphrase: Buffer,
    privateKey: string
  ): Buffer {
    return crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
      encryptedPassphrase
    );
  }

  /**
   * Decrypts the payload using the decrypted passphrase.
   * @param payload - The binary payload containing the "Salted__" prefix, salt, and encrypted data.
   * @param passphrase - The passphrase used to derive the encryption key and IV.
   * @returns The decrypted payload as a UTF-8 string.
   */
  public decryptPayload(payload: Buffer, passphrase: Buffer): string {
    if (payload.subarray(0, 8).toString() !== this.SALTED_PREFIX) {
      throw new Error(
        `Payload does not have the expected ${this.SALTED_PREFIX} prefix.`
      );
    }

    // Extract the salt (next 8 bytes after the prefix)
    const salt = payload.subarray(8, 16);

    // Extract the encrypted data (everything after the salt)
    const encryptedData = payload.subarray(16);

    const derivedKey = crypto.pbkdf2Sync(
      passphrase,
      salt,
      this.PBKDF2_ITERATIONS,
      this.AES_KEY_LENGTH + this.AES_IV_LENGTH,
      this.PBKDF2_HASH
    );

    // Use subarray for key and IV extraction
    const key = derivedKey.subarray(0, this.AES_KEY_LENGTH);
    const iv = derivedKey.subarray(
      this.AES_KEY_LENGTH,
      this.AES_KEY_LENGTH + this.AES_IV_LENGTH
    );

    const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv);
    const decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  }

  /**
   * Verifies the digital signature of the passphrase using the public key.
   * @param passphrase - The passphrase as binary data.
   * @param signature - The digital signature as binary data.
   * @param publicKey - The public key used to verify the signature.
   * @returns `true` if the signature is valid, `false` otherwise.
   */
  public verifySignature(
    passphrase: Buffer,
    signature: Buffer,
    publicKey: string
  ): boolean {
    const verifier = crypto.createVerify("sha256");
    verifier.update(passphrase);
    verifier.end();
    return verifier.verify(publicKey, signature);
  }
}
