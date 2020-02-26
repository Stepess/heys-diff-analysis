package ua.stepess.crypto.cipher;

public interface BlockCipher {

    int encrypt(int plaintext, String key);

    int decrypt(int cyphertext, String key);

}
