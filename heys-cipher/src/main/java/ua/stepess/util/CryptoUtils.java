package ua.stepess.util;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ThreadLocalRandom;

import static ua.stepess.crypto.diff.DifferentialAttack.VECTORS_NUM;

public class CryptoUtils {

    public static int[] generateKey() {
        var keys = new int[7];

        for (int i = 0; i < keys.length; i++) {
            keys[i] = ThreadLocalRandom.current().nextInt(VECTORS_NUM);
        }

        return keys;
    }

    public static void createPlaintexts() {
        int[] input = generatePlaintext(8 * VECTORS_NUM / 5);

        writeAsBinary(input, "tmp/linear/input");
    }

    public static void createPlaintexts(int a, int size) {
        int[] input = generatePlaintextWithDifference(size, a);

        writeAsBinary(input, "tmp/diff/input");
    }

    public static void writeAsBinary(int[] input, String filename) {
        try {
            Files.write(Path.of(filename), toByteArray(input));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static int[] read(String filename) {
        try {
            return toIntArray(Files.readAllBytes(Path.of(filename)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static int[] toIntArray(byte[] bytes) {
        int[] ints = new int[bytes.length / 2];
        for (int i = 0; i < ints.length; i++) {
            ints[i] = Byte.toUnsignedInt(bytes[2 * i]) | (Byte.toUnsignedInt(bytes[2 * i + 1]) << Byte.SIZE);
        }
        return ints;
    }

    private static byte[] toByteArray(int[] ints) {
        byte[] bytes = new byte[2 * ints.length];
        for (int i = 0; i < ints.length; i++) {
            bytes[2 * i] = (byte) ints[i];
            bytes[2 * i + 1] = (byte) (ints[i] >>> Byte.SIZE);
        }
        return bytes;
    }

    public static int[] generatePlaintext(int size) {
        int[] ints = new int[size];
        for (int i = 0; i < size; i++) {
            ints[i] = ThreadLocalRandom.current().nextInt(VECTORS_NUM);
        }
        return ints;
    }

    public static int[] generatePlaintextWithDifference(int size, int diff) {
        int[] ints = new int[2 * size];
        for (int i = 0; i < size; i++) {
            ints[2 * i] = ThreadLocalRandom.current().nextInt(VECTORS_NUM);
            ints[2 * i + 1] = ints[2 * i] ^ diff;
        }
        return ints;
    }
}
