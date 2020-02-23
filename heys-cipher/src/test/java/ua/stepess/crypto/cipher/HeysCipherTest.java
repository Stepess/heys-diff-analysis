package ua.stepess.crypto.cipher;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static java.lang.Integer.parseInt;
import static org.junit.jupiter.api.Assertions.*;

class HeysCipherTest {

    private HeysCipher cipher = new HeysCipher(4);

    @Test
    void shouldPartitionBlock() {
        int block = parseInt("1101001100101110", 2);

        int[] expectedBlocks = Arrays.stream(new String[]{"1101", "0011", "0010", "1110"})
                .mapToInt(s -> parseInt(s, 2))
                .toArray();

        int[] actualBlocks = cipher.partitionBlock(block);

        assertArrayEquals(expectedBlocks, actualBlocks);
    }
}