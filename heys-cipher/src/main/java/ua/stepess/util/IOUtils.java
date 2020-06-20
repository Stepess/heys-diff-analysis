package ua.stepess.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
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

}
