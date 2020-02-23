package ua.stepess.crypto.cipher;

public interface BlockCipher {

    int encrypt(int plaintext, int key);

    int decrypt(int cyphertext, int key);

}
