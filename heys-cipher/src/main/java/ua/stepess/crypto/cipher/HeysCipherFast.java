package ua.stepess.crypto.cipher;

import ua.stepess.crypto.SBox;
import ua.stepess.util.HeysCipherFactory;

import java.util.Arrays;
import java.util.Random;
import java.util.stream.IntStream;

import static java.lang.Integer.parseInt;

public class HeysCipherFast implements BlockCipher {

    public static final String ONE = "1";

    private int n;
    private int mask;
    private int numOfRounds;
    private SBox sBox;

    private static final int[] S_BOX = new int[] {
            0x8, 0x0, 0xC, 0x4, 0x9, 0x6, 0x7, 0xB, 0x2, 0x3, 0x1, 0xF, 0x5, 0xE, 0xA, 0xD
    };

    public HeysCipherFast(int n, int numOfRounds, SBox sBox) {
        this.n = n;
        this.mask = parseInt(ONE.repeat(Math.max(0, n)), 2);
        this.numOfRounds = numOfRounds;
        this.sBox = sBox;
    }

    public static void main(String[] args) {
        BlockCipher cipher = HeysCipherFactory.getDefaultHeysCipher();
        int numOfExperiments = 10_000_000;
        long[] time = new long[numOfExperiments];
        Random random = new Random();

        for (int i = 0; i < numOfExperiments; i++) {
            int block = random.nextInt(65536);
            long b = System.currentTimeMillis();
            int c = cipher.doDecryptionRound(block, 0x1234);
            time[i] = System.currentTimeMillis() - b;

            c++;
            doNothing(c);
        }

        System.out.println("Average: " + Arrays.stream(time).average());
    }

    private static void doNothing(int i) {

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
        for (int i = 0; i < numOfRounds; i++) {
            block = doEncryptionRound(block, roundKeys[i]);
        }

        return block ^ roundKeys[numOfRounds];
    }

    @Override
    public int encryptBlock(int block, String key) {
        int[] roundKeys = generateRoundKeys(key);

        return encryptBlock(block, roundKeys);
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
        return shuffle(substitute(x ^ k));
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

    int shuffle(int block) {
        int temp = block;
        block = 0;
        block |= (temp & 0x8421);
        block |= (temp & 0x0842) << 3;
        block |= (temp & 0x0084) << 6;
        block |= (temp & 0x0008) << 9;
        block |= (temp & 0x4210) >> 3;
        block |= (temp & 0x2100) >> 6;
        block |= (temp & 0x1000) >> 9;
        return block;
    }

    int substitute(int block) {
        int b = block;

        int nibble = b & 0xF;
        int temp = (sBox.substitute(nibble));
        b &= 0xFFF0;
        b |= temp;

        nibble = (b >> 4) & 0xF;
        temp = (sBox.substitute(nibble) << 4);
        b &= 0xFF0F;
        b |= temp;

        nibble = (b >> 8) & 0xF;
        temp = (sBox.substitute(nibble) << 8);
        b &= 0xF0FF;
        b |= temp;

        nibble = (b >> 12) & 0xF;
        temp = (sBox.substitute(nibble) << 12);
        b &= 0x0FFF;
        b |= temp;

        return b;
    }

    int reverseSubstitute(int block) {
        int b = block;

        int nibble = b & 0xF;
        int temp = (sBox.reverseSubstitute(nibble));
        b &= 0xFFF0;
        b |= temp;

        nibble = (b >> 4) & 0xF;
        temp = (sBox.reverseSubstitute(nibble) << 4);
        b &= 0xFF0F;
        b |= temp;

        nibble = (b >> 8) & 0xF;
        temp = (sBox.reverseSubstitute(nibble) << 8);
        b &= 0xF0FF;
        b |= temp;

        nibble = (b >> 12) & 0xF;
        temp = (sBox.reverseSubstitute(nibble) << 12);
        b &= 0x0FFF;
        b |= temp;

        return b;
    }

    private int setBitAt(int number, int bitPosition) {
        return number | 1 << bitPosition;
    }

    private int getBitAt(int number, int bitPosition) {
        return number >> bitPosition & 1;
    }

    @Override
    public int decryptBlock(int block, int[] roundKeys) {
        for (int i = numOfRounds; i > 0; i--) {
            block = doDecryptionRound(block, roundKeys[i]);
        }

        return block ^ roundKeys[0];
    }


    @Override
    public int decryptBlock(int block, String key) {
        int[] roundKeys = generateRoundKeys(key);

        return decryptBlock(block, roundKeys);
    }

    @Override
    public int doDecryptionRound(int x, int k) {
        return reverseSubstitute(shuffle(x ^ k));
    }
}
