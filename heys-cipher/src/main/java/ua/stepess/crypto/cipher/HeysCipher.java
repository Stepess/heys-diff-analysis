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

        var shuffledBlocks = shuffle(substitutedBlocks);

        return convertToInt(shuffledBlocks);
    }

    int[] partitionBlock(int block) {
        int[] partitioned = new int[n];

        for (int i = 0; i < n; i++) {
            partitioned[i] = (block >> (n * (n - i - 1))) & mask;
        }

        return partitioned;
    }

    int convertToInt(int[] blocks) {
        int number = 0;

        for (int i = 0; i < blocks.length; i++) {
            for (int j = 0; j < n; j++) {
                number |= blocks[n - i - 1] << n * i;
            }
        }

        return number;
    }

    int[] shuffle(int[] blocks) {
        int bit;

        int[] shuffledBlocks = new int[n];

        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                bit = getBitAt(blocks[j], n - i - 1);

                if (bit == 1) {
                    shuffledBlocks[i] = setBitAt(shuffledBlocks[i], n - j - 1);
                }
            }
        }

        return shuffledBlocks;
    }

    private int setBitAt(int number, int bitPosition) {
        return number | 1 << bitPosition;
    }

    private int getBitAt(int number, int bitPosition) {
        return number >> bitPosition & 1;
    }

    @Override
    public int decrypt(int cyphertext, int key) {
        return 0;
    }
}
