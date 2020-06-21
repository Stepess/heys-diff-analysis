package ua.stepess.crypto.cipher;

public interface BlockCipher {

    byte[] encrypt(byte[] plaintext, String key);

    byte[] encrypt(byte[] plaintext, int[] key);

    byte[] decrypt(byte[] ciphertext, String key);

    byte[] decrypt(byte[] ciphertext, int[] key);

    int encryptBlock(int block, String key);

    int encryptBlock(int block, int[] key);

    int decryptBlock(int block, String key);

    int decryptBlock(int block, int[] key);

    int doEncryptionRound(int block, int key);

    int doDecryptionRound(int block, int key);
}
