package ua.stepess.crypto.cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ua.stepess.crypto.SBox;

import java.util.Arrays;
import java.util.stream.IntStream;

import static java.lang.Integer.parseInt;

public class HeysCipher implements BlockCipher {

    private static final Logger log = LoggerFactory.getLogger(HeysCipher.class);

    public static final String ONE = "1";

    private int n;
    private int mask;
    private int numOfRounds;
    private SBox sBox;

    public HeysCipher(int n, int numOfRounds, SBox sBox) {
        this.n = n;
        this.mask = parseInt(ONE.repeat(Math.max(0, n)), 2);
        this.numOfRounds = numOfRounds;
        this.sBox = sBox;
    }

    @Override
    public int encrypt(int plaintext, String key) {
        int[] roundKeys = generateRoundKeys(key);

        log.debug("Generated round keys [{}]", Arrays.toString(roundKeys));

        for (int i = 0; i < numOfRounds; i++) {
            log.debug("Start round #{}, ciphertext [{}], round key [{}]", i, plaintext, roundKeys[i]);
            plaintext = doEncryptionRound(plaintext, roundKeys[i]);
            log.debug("Finish round #{}, ciphertext [{}]", i, plaintext);
        }

        return plaintext ^ roundKeys[numOfRounds];
    }

    int[] generateRoundKeys(String key) {
        return IntStream.range(0, numOfRounds + 1)
                .mapToObj(i -> key.substring(i * n, (i + 1) * n))
                .mapToInt(hex -> parseInt(hex, 16))
                .toArray();
    }

    int doEncryptionRound(int x, int k) {
        int y = x ^ k;
        log.debug("y = {}", y);

        var blocks = partitionOnBlocks(y);
        log.debug("Round blocks {}", Arrays.toString(blocks));


        var substitutedBlocks = Arrays.stream(blocks)
                .map(sBox::substitute)
                .toArray();

        var shuffledBlocks = shuffle(substitutedBlocks);
        log.debug("Round blocks after transformations {}", Arrays.toString(shuffledBlocks));
        return convertToInt(shuffledBlocks);
    }

    int[] partitionOnBlocks(int block) {
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
    public int decrypt(int ciphertext, String key) {
        int[] roundKeys = generateRoundKeys(key);

        log.debug("Generated round keys [{}]", Arrays.toString(roundKeys));

        ciphertext = ciphertext ^ roundKeys[numOfRounds];

        for (int i = numOfRounds - 1; i > -1; i--) {
            log.debug("Start round #{}, ciphertext [{}], round key [{}]", i, ciphertext, roundKeys[i]);
            ciphertext = doDecryptionRound(ciphertext, roundKeys[i]);
            log.debug("Finish round #{}, ciphertext [{}]", i, ciphertext);

        }

        return ciphertext;
    }

    int doDecryptionRound(int x, int k) {
        var shuffledBlocks = partitionOnBlocks(x);
        log.debug("Round blocks {}", Arrays.toString(shuffledBlocks));

        var blocks = shuffle(shuffledBlocks);

        var substitutedBlocks = Arrays.stream(blocks)
                .map(sBox::reverseSubstitute)
                .toArray();

        log.debug("Round blocks after transformations  {}", Arrays.toString(substitutedBlocks));

        int i = convertToInt(substitutedBlocks);
        log.debug("y = {}", i);
        return i ^ k;
    }
}
