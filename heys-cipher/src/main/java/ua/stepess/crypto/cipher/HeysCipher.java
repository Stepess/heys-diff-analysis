package ua.stepess.crypto.cipher;

import ua.stepess.crypto.SBox;

import java.util.Arrays;

import static java.lang.Integer.parseInt;

public class HeysCipher implements BlockCipher {

    public static final String ONE = "1";

    private int n;
    private int mask;
    private SBox sBox;

    public HeysCipher(int n, SBox sBox) {
        this.n = n;
        this.mask = parseInt(ONE.repeat(Math.max(0, n)), 2);
        this.sBox = sBox;
    }

    @Override
    public int encrypt(int plaintext, int key) {
        return 0;
    }

    private int round(int x, int k) {
        int y = x ^ k;

        var blocks = partitionBlock(y);

        var substitutedBlocks = Arrays.stream(blocks)
                .map(sBox::substitute)
                .toArray();



        return 0;
    }

    int[] partitionBlock(int block) {
        int[] partitioned = new int[n];

        for (int i = 0; i < n; i++) {
            partitioned[i] = (block >> (n * (n - i - 1))) & mask;
        }

        return partitioned;
    }

    int[] shuffle(int[] blocks) {
        return null;
    }

    @Override
    public int decrypt(int cyphertext, int key) {
        return 0;
    }
}
