package ua.stepess.crypto.cipher;

import org.junit.jupiter.api.Test;
import ua.stepess.crypto.SBox;

import java.util.Arrays;

import static java.lang.Integer.parseInt;
import static org.junit.jupiter.api.Assertions.*;

class HeysCipherTest {

    private HeysCipher cipher = new HeysCipher(4, new SBox(new int[0]));

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
    void shouldConvertToInt() {
        int[] blocks = Arrays.stream(new String[]{"1101", "0011", "0010", "1110"})
                .mapToInt(s -> parseInt(s, 2))
                .toArray();

        int expectedNumber = parseInt("1101001100101110", 2);

        int actualNumber = cipher.convertToInt(blocks);

        assertEquals(expectedNumber, actualNumber);
    }
}