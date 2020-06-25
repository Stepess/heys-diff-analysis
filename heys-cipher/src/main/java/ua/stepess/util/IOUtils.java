package ua.stepess.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ua.stepess.crypto.linear.Approximation;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;

public class IOUtils {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static Map<Integer, Map<Integer, Double>> readDifferentialsFromFile(String fileName) throws IOException {
        var srcFile = new File(fileName);
        return OBJECT_MAPPER.readValue(srcFile, new TypeReference<>() {
        });
    }

    public static void writeDifferentialsToDisk(String fileName, Map<Integer, Map<Integer, Double>> searchResult) throws IOException {
        var file = new File(fileName);

        OBJECT_MAPPER.writeValue(file, searchResult);
    }

    public static void writeToDiskAsJson(String fileName, Object data) {
        var file = new File(fileName);

        try {
            OBJECT_MAPPER.writeValue(file, data);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static List<Approximation> readApproximations(String fileName) {
        var srcFile = new File(fileName);

        try {
            return OBJECT_MAPPER.readValue(srcFile, new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
