package ua.stepess.crypto.cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ua.stepess.crypto.SBox;

import java.util.Arrays;
import java.util.stream.Collectors;
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

        log.debug("Generated round keys [{}]", toHexString(roundKeys));

        plaintext = Integer.reverseBytes(plaintext);

        for (int i = 0; i < numOfRounds; i++) {
            log.debug("Round #{}", i);
            log.debug("plaintext: {} : {}", Integer.toHexString(plaintext), Integer.toBinaryString(plaintext));
            log.debug("key: {} : {}", Integer.toHexString(roundKeys[i]), Integer.toBinaryString(roundKeys[i]));
            plaintext = doEncryptionRound(plaintext, roundKeys[i]);
            log.debug("Finish round #{}, ciphertext: {} : {}", i,
                    Integer.toHexString(plaintext), Integer.toBinaryString(plaintext));
        }

        var res = plaintext ^ roundKeys[numOfRounds];

        res = res >> 16;
        return res;
    }

    private String toHexString(int[] roundKeys) {
        return Arrays.stream(roundKeys).mapToObj(Integer::toHexString)
                .collect(Collectors.joining(" "));
    }

    int[] generateRoundKeys(String key) {
        return IntStream.range(0, numOfRounds + 1)
                .mapToObj(i -> key.substring(i * n, (i + 1) * n))
                .mapToInt(hex -> parseInt(hex, 16))
                .map(Integer::reverseBytes)
                .toArray();
    }

    int doEncryptionRound(int x, int k) {
        int y = x ^ k;
        log.debug("x ^ k: {} : {}", Integer.toHexString(y), Integer.toBinaryString(y));

        var blocks = partitionOnBlocks(y);

        var substitutedBlocks = Arrays.stream(blocks)
                .map(sBox::substitute)
                .toArray();

        var num = convertToInt(substitutedBlocks);
        log.debug("S(x): {} : {}", Integer.toHexString(num), Integer.toBinaryString(num));

        var shuffledBlocks = shuffle(substitutedBlocks);

        return convertToInt(shuffledBlocks);
    }

    // TODO: what should we do if number bitlength bigger then 16
    int[] partitionOnBlocks(int number) {
        int[] partitioned = new int[n];

        for (int i = 1; i <= n; i++) {
            partitioned[i-1] = (number >> (32 - n * i)) & mask;
        };

        /*for (int i = 0; i < n; i++) {
            partitioned[i] = (number >> (n * (n - i - 1))) & mask;
        }*/

        return partitioned;
    }

    int convertToInt(int[] blocks) {
        int number = 0;

        for (int i = 0; i < n; i++) {
            number |= blocks[n - i - 1] << n * i;
        }

        number = number << 16;

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

        var blocks = shuffle(shuffledBlocks);

        var substitutedBlocks = Arrays.stream(blocks)
                .map(sBox::reverseSubstitute)
                .toArray();

        return convertToInt(substitutedBlocks) ^ k;
    }
}
