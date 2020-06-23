package ua.stepess.crypto.cipher;

public class HeysCipherFast implements BlockCipher {
    public static final int SUB_BLOCK_SIZE = 4;
    public static final int BLOCK_SIZE = 16;

    public static final int ROUNDS = 6;

    private static int[] PERMUTATION = computePermutation();

    private static final int[] S_BOX = new int[] {
            0x8, 0x0, 0xC, 0x4, 0x9, 0x6, 0x7, 0xB, 0x2, 0x3, 0x1, 0xF, 0x5, 0xE, 0xA, 0xD
    };

    private static final int[] INV_S_BOX = inverseSBox(S_BOX);

    @Override
    public int encryptBlock(int data, int[] keys) {
        int ciphertext = data;
        for (int i = 0; i < ROUNDS; i++) {
            ciphertext = doEncryptionRound(ciphertext, keys[i]);
        }
        return addKey(ciphertext, keys[ROUNDS]);
    }

    @Override
    public int doEncryptionRound(int data, int key) {
        return permutation(substitution(addKey(data, key), S_BOX));
    }

    @Override
    public int decryptBlock(int data, int[] keys) {
        int message = data;
        for (int i = ROUNDS; i > 0; i--) {
            message = doDecryptionRound(message, keys[i]);
        }
        return addKey(message, keys[0]);
    }

    public int doDecryptionRound(int data, int key) {
        return substitution(permutation(addKey(data, key)), INV_S_BOX);
    }

    public int permutation(int data) {
        return PERMUTATION[data];
    }

    private int substitution(int data, int[] sBox) {
        int result = 0;
        for (int i = 0; i < SUB_BLOCK_SIZE; i++) {
            result |= (sBox[(data >>> (SUB_BLOCK_SIZE * i)) & 0xF] << (SUB_BLOCK_SIZE * i));
        }
        return result;
    }

    public int substitution(int data) {
        return substitution(data, S_BOX);
    }

    public int inverseSubstitution(int data) {
        return substitution(data, INV_S_BOX);
    }

    public int addKey(int data, int key) {
        return data ^ key;
    }

    private static int[] inverseSBox(int[] sBox) {
        int[] inverseBox = new int[sBox.length];
        for (int i = 0; i < sBox.length; i++) {
            inverseBox[sBox[i]] = i;
        }
        return inverseBox;
    }

    private static int[] computePermutation() {
        int[] table = new int[1 << HeysCipherFast.BLOCK_SIZE];
        for (int i = 0; i < table.length; i++) {
            table[i] = rawPermutation(i);
        }
        return table;
    }

    private static int rawPermutation(int data) {
        int result = 0;
        for (int i = 0; i < SUB_BLOCK_SIZE; i++) {
            for (int j = 0; j < SUB_BLOCK_SIZE; j++) {
                int bit = (data >>> (SUB_BLOCK_SIZE * j + i)) & 0x1;
                result |= (bit << (SUB_BLOCK_SIZE * i + j));
            }
        }
        return result;
    }

    @Override
    public byte[] encrypt(byte[] plaintext, String key) {
        return new byte[0];
    }

    @Override
    public byte[] encrypt(byte[] plaintext, int[] key) {
        return new byte[0];
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, String key) {
        return new byte[0];
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, int[] key) {
        return new byte[0];
    }

    @Override
    public int encryptBlock(int block, String key) {
        return 0;
    }

    @Override
    public int decryptBlock(int block, String key) {
        return 0;
    }
}
