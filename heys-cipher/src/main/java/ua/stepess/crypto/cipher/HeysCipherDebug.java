package ua.stepess.crypto.cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ua.stepess.crypto.SBox;

import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.lang.Integer.parseInt;

public class HeysCipherDebug implements BlockCipher {

    private static final Logger log = LoggerFactory.getLogger(HeysCipherDebug.class);

    public static final String ONE = "1";

    private int n;
    private int mask;
    private int numOfRounds;
    private SBox sBox;

    public HeysCipherDebug(int n, int numOfRounds, SBox sBox) {
        this.n = n;
        this.mask = parseInt(ONE.repeat(Math.max(0, n)), 2);
        this.numOfRounds = numOfRounds;
        this.sBox = sBox;
    }

    @Override
    public byte[] encrypt(byte[] plaintext, String key) {
        var blocks = splitInputToBlocks(plaintext);
        var encryptedBlocks = Arrays.stream(blocks)
                .map(b -> encryptBlock(b, key))
                .toArray();
        return convertBlocksToBytes(encryptedBlocks);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, int[] keys) {
        var blocks = splitInputToBlocks(plaintext);
        var encryptedBlocks = Arrays.stream(blocks)
                .map(b -> encryptBlock(b, keys))
                .toArray();
        return convertBlocksToBytes(encryptedBlocks);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, String key) {
        var blocks = splitInputToBlocks(ciphertext);
        var decryptedBlocks = Arrays.stream(blocks)
                .map(b -> decryptBlock(b, key))
                .toArray();
        return convertBlocksToBytes(decryptedBlocks);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, int[] keys) {
        var blocks = splitInputToBlocks(ciphertext);
        var decryptedBlocks = Arrays.stream(blocks)
                .map(b -> decryptBlock(b, keys))
                .toArray();
        return convertBlocksToBytes(decryptedBlocks);
    }

    int[] splitInputToBlocks(byte[] in) {
        in = addPadding(in);

        int[] blocks = new int[in.length / 2];

        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = ((in[2 * i + 1] & 0xff) << 8) ^ in[2 * i] & 0xff;
        }

        return blocks;
    }

    private byte[] addPadding(byte[] in) {
        if (in.length % 2 != 0) {
            byte[] padded = new byte[in.length + 1];
            System.arraycopy(in, 0, padded, 1, in.length);
            padded[0] = '\n';
            in = padded;
        }
        return in;
    }

    byte[] convertBlocksToBytes(int[] blocks) {
        byte[] out = new byte[blocks.length * 2];

        for (int i = 0; i < blocks.length; i++) {
            out[2 * i] = (byte) (blocks[i] & 0xff);
            out[2 * i + 1] = (byte) ((blocks[i] >>> 8) & 0xff);
        }

        return out;
    }

    @Override
    public int encryptBlock(int block, int[] roundKeys) {
        log.debug("Generated round keys [{}]", toHexString(roundKeys));

        block = toLittleEndian(block);

        for (int i = 0; i < numOfRounds; i++) {
            log.debug("========= Start Round #{} =========", i);
            log.debug("plaintext:  {} : {}", Integer.toHexString(block), Integer.toBinaryString(block));
            log.debug("key:        {} : {}", Integer.toHexString(roundKeys[i]), Integer.toBinaryString(roundKeys[i]));
            block = doEncryptionRound(block, roundKeys[i]);
            log.debug("ciphertext: {} : {}", Integer.toHexString(block), Integer.toBinaryString(block));
        }

        log.debug("========= Start Round #{} =========", numOfRounds);
        log.debug("plaintext:  {} : {}", Integer.toHexString(block), Integer.toBinaryString(block));
        log.debug("key:        {} : {}", Integer.toHexString(roundKeys[numOfRounds]), Integer.toBinaryString(roundKeys[numOfRounds]));
        var ciphertext = block ^ roundKeys[numOfRounds];
        log.debug("ciphertext: {} : {}", Integer.toHexString(ciphertext), Integer.toBinaryString(ciphertext));

        return ciphertext;
    }

    @Override
    public int encryptBlock(int block, String key) {
        int[] roundKeys = generateRoundKeys(key);

        return encryptBlock(block, roundKeys);
    }

    private String toHexString(int[] roundKeys) {
        return Arrays.stream(roundKeys).mapToObj(Integer::toHexString)
                .collect(Collectors.joining(" "));
    }

    private int toLittleEndian(int num) {
        return Integer.reverseBytes(num) >>> 16;
    }

    int[] generateRoundKeys(String key) {
        return IntStream.range(0, numOfRounds + 1)
                .mapToObj(i -> key.substring(i * n, (i + 1) * n))
                .mapToInt(hex -> parseInt(hex, 16))
                .map(this::toLittleEndian)
                .toArray();
    }

    @Override
    public int doEncryptionRound(int x, int k) {
        int y = x ^ k;
        log.debug("x ^ k:      {} : {}", Integer.toHexString(y), Integer.toBinaryString(y));

        var blocks = partitionOnBlocks(y);

        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = sBox.substitute(blocks[i]);
        }

        var substituted = convertToInt(blocks);
        log.debug("S(x):       {} : {}", Integer.toHexString(substituted), Integer.toBinaryString(substituted));

        var shuffledBlocks = shuffle(blocks);

        return convertToInt(shuffledBlocks);
    }

    // TODO: what should we do if number bitlength bigger then 16
    int[] partitionOnBlocks(int number) {
        int[] partitioned = new int[n];

        for (int i = 0; i < n; i++) {
            partitioned[i] = number >> (12 - n * i) & mask;
        }

        return partitioned;
    }

    int convertToInt(int[] blocks) {
        int number = 0;

        for (int i = 0; i < n; i++) {
            number |= blocks[n - i - 1] << n * i;
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
    public int decryptBlock(int block, int[] roundKeys) {
        log.debug("Generated round keys [{}]", toHexString(roundKeys));

        log.debug("========= Start Round #{} =========", numOfRounds);
        log.debug("ciphertext:  {} : {}", Integer.toHexString(block), Integer.toBinaryString(block));
        log.debug("key:         {} : {}", Integer.toHexString(roundKeys[numOfRounds]), Integer.toBinaryString(roundKeys[numOfRounds]));
        block = block ^ roundKeys[numOfRounds];
        log.debug("plaintext:   {} : {}", Integer.toHexString(block), Integer.toBinaryString(block));

        for (int i = numOfRounds - 1; i > -1; i--) {
            log.debug("========= Start Round #{} =========", i);
            log.debug("ciphertext:  {} : {}", Integer.toHexString(block), Integer.toBinaryString(block));
            log.debug("key:         {} : {}", Integer.toHexString(roundKeys[i]), Integer.toBinaryString(roundKeys[i]));
            block = doDecryptionRound(block, roundKeys[i]);
            log.debug("plaintext:   {} : {}", Integer.toHexString(block), Integer.toBinaryString(block));
        }

        block = toLittleEndian(block);

        return block;
    }

    @Override
    public int decryptBlock(int block, String key) {
        int[] roundKeys = generateRoundKeys(key);

        return decryptBlock(block, roundKeys);
    }

    @Override
    public int doDecryptionRound(int x, int k) {
        var shuffledBlocks = partitionOnBlocks(x);

        var blocks = shuffle(shuffledBlocks);

        var substitutedBlocks = Arrays.stream(blocks)
                .map(sBox::reverseSubstitute)
                .toArray();

        return convertToInt(substitutedBlocks) ^ k;
    }
}
