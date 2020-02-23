package ua.stepess.crypto.cipher;

import static java.lang.Integer.parseInt;

public class HeysCipher implements BlockCipher {

    public static final String ONE = "1";

    private int n;
    private int mask;

    public HeysCipher(int n) {
        this.n = n;

        this.mask = parseInt(ONE.repeat(Math.max(0, n)), 2);
    }

    @Override
    public int encrypt(int plaintext, int key) {
        return 0;
    }

    private int round(int x, int k) {
        int y = x ^ k;

        return 0;
    }

    int[] partitionBlock(int block) {
        int[] partitioned = new int[n];

        for (int i = 0; i < n; i++) {
            partitioned[i] = (block >> (n * (n - i - 1))) & mask;
        }

        return partitioned;
    }

    @Override
    public int decrypt(int cyphertext, int key) {
        return 0;
    }
}
