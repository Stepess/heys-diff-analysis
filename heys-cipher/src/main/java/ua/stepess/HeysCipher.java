package ua.stepess;

import java.util.Arrays;
import java.util.Random;

public class HeysCipher {
    public static final HeysCipher INSTANCE = new HeysCipher();

    public static final int SUB_BLOCK_SIZE = 4;
    public static final int BLOCK_SIZE = 16;

    public static final int ROUNDS = 6;

    private static int[] PERMUTATION = computePermutation();

    private static final int[] S_BOX = new int[] {
            0x8, 0x0, 0xC, 0x4, 0x9, 0x6, 0x7, 0xB, 0x2, 0x3, 0x1, 0xF, 0x5, 0xE, 0xA, 0xD
    };

    public static void main(String[] args) {
        HeysCipher cipher = HeysCipher.INSTANCE;
        int numOfExperiments = 10_000_000;
        long[] time = new long[numOfExperiments];
        Random random = new Random();

        for (int i = 0; i < numOfExperiments; i++) {
            int block = random.nextInt(65536);
            long b = System.currentTimeMillis();
            int c = cipher.decryptRound(block, 0x1234);
            time[i] = System.currentTimeMillis() - b;

            c++;
            doNothing(c);
        }

        System.out.println("Average: " + Arrays.stream(time).average());
    }

    private static void doNothing(int i) {

    }

    private static final int[] INV_S_BOX = inverseSBox(S_BOX);

    public int encrypt(int data, int[] keys) {
        int ciphertext = data;
        for (int i = 0; i < ROUNDS; i++) {
            ciphertext = encryptRound(ciphertext, keys[i]);
        }
        return addKey(ciphertext, keys[ROUNDS]);
    }

    public int encryptRound(int data, int key) {
        return permutation(substitution(addKey(data, key), S_BOX));
    }

    public int decrypt(int data, int[] keys) {
        int message = data;
        for (int i = 0; i < ROUNDS; i++) {
            message = decryptRound(message, keys[i]);
        }
        return addKey(message, keys[ROUNDS]);
    }

    public int decryptRound(int data, int key) {
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
        int[] table = new int[1 << HeysCipher.BLOCK_SIZE];
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
}
