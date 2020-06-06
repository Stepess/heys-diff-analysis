package ua.stepess.crypto.cipher;

public interface BlockCipher {

    int encryptBlock(int plaintext, String key);

    int decryptBlock(int ciphertext, String key);

}
