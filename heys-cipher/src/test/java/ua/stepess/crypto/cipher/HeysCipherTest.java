package ua.stepess.crypto.cipher;

import org.junit.jupiter.api.Test;
import ua.stepess.crypto.SBox;
import ua.stepess.util.SBoxFactory;

import java.util.Arrays;

import static java.lang.Integer.parseInt;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class HeysCipherTest {

    private HeysCipher cipher = new HeysCipher(4, 6, SBoxFactory.getDefaultSBox());

    @Test
    void shouldEncrypt() {
        var key = "3bd8747b5ae4d28650bed1f8e902";
        int plaintext = 1;

        int ciphertext = cipher.encrypt(plaintext, key);

        System.out.println(ciphertext);
    }

    @Test
    void shouldSplitKey() {
        var key = "922da047bcb4145967f66f16a422";

        int[] roundKeys = cipher.generateRoundKeys(key);

        assertEquals(7, roundKeys.length);
    }

    @Test
    void shouldPartitionBlock() {
        int block = parseInt("1101001100101110", 2);

        int[] expectedBlocks = Arrays.stream(new String[]{"1101", "0011", "0010", "1110"})
                .mapToInt(s -> parseInt(s, 2))
                .toArray();

        int[] actualBlocks = cipher.partitionBlock(block);

        assertArrayEquals(expectedBlocks, actualBlocks);
    }

    @Test
    void shouldShuffleBlocks() {
        int[] initialBlocks = Arrays.stream(new String[]{"1100", "1001", "1000", "0110"})
                .mapToInt(s -> parseInt(s, 2))
                .toArray();

        int[] expectedBlocks = Arrays.stream(new String[]{"1110", "1001", "0001", "0100"})
                .mapToInt(s -> parseInt(s, 2))
                .toArray();

        int[] actualBlocks = cipher.shuffle(initialBlocks);

        assertArrayEquals(expectedBlocks, actualBlocks);
    }

    @Test
    void shouldShuffleBlocksExampleFromSpecification() {
        int[] initialBlocks = Arrays.stream(new String[]{"0111", "1010", "0001", "1101"})
                .mapToInt(s -> parseInt(s, 2))
                .toArray();

        int[] expectedBlocks = Arrays.stream(new String[]{"0101", "1001", "1100", "1011"})
                .mapToInt(s -> parseInt(s, 2))
                .toArray();

        int[] actualBlocks = cipher.shuffle(initialBlocks);

        assertArrayEquals(expectedBlocks, actualBlocks);
    }

    @Test
    void shouldConvertToInt() {
        int[] blocks = Arrays.stream(new String[]{"1101", "0011", "0010", "1110"})
                .mapToInt(s -> parseInt(s, 2))
                .toArray();

        int expectedNumber = parseInt("1101001100101110", 2);

        int actualNumber = cipher.convertToInt(blocks);

        assertEquals(expectedNumber, actualNumber);
    }

    @Test
    void shouldConvertToIntExampleFromDocs() {
        int[] blocks = Arrays.stream(new String[]{"0111", "1010", "0001", "1101"})
                .mapToInt(s -> parseInt(s, 2))
                .toArray();

        int expectedNumber = parseInt("7A1D", 16);

        int actualNumber = cipher.convertToInt(blocks);

        assertEquals(expectedNumber, actualNumber);
    }
}