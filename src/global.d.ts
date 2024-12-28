declare namespace NodeJS {
  interface ProcessEnv {
    SALTED_PREFIX: string;
    AES_KEY_LENGTH: string;
    AES_IV_LENGTH: string;
    PBKDF2_ITERATIONS: string;
    PBKDF2_HASH: string;
    ALGORITHM: string;
    PUBLIC_KEY_PATH: string;
    PRIVATE_KEY_PATH: string;
    MESSAGE_PATH: string;
  }
}
