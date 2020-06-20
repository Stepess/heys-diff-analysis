package ua.stepess.util;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import ua.stepess.analysis.Pair;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

public final class FileUtil {
    private static final Gson GSON = new Gson();

    private static final Type COLLECTION_PAIRS_TYPE = new TypeToken<List<Pair>>(){}.getType();

    private FileUtil() { }

    public static void write(Path path, int[] data) {
        try {
            Files.write(path, toByteArray(data));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static int[] read(Path path) {
        try {
            return toIntArray(Files.readAllBytes(path));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void write(Path path, Collection<Pair> pairs) {
        try {
            Files.write(path, GSON.toJson(pairs).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Collection<Pair> readPairs(Path path) {
        try {
            return GSON.fromJson(new String(Files.readAllBytes(path), StandardCharsets.UTF_8), COLLECTION_PAIRS_TYPE);
        } catch (Exception e) {
            throw new RuntimeException();
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
}
