package ua.stepess.crypto.cipher;

public interface BlockCipher {

    byte[] encrypt(byte[] plaintext, String key);

    byte[] decrypt(byte[] ciphertext, String key);

    int encryptBlock(int block, String key);

    int decryptBlock(int block, String key);

}
