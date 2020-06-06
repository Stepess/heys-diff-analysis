package ua.stepess.crypto.diff;

import com.fasterxml.jackson.databind.ObjectMapper;
import ua.stepess.crypto.cipher.BlockCipher;
import ua.stepess.util.HeysCipherFactory;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class DifferentialSearch {

    public static final int VECTORS_NUM = 0x10000;

    public static final BlockCipher HEYS = HeysCipherFactory.getDefaultHeysCipher();
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static final String DEFAULT_KEY = "a1722101d9e038caa7b4d120c18b";

    public static void main(String[] args) throws IOException {
        /*int[] alphas = {0xf000, 0x0f00, 0x00f0, 0x000f,
                0x1000, 0x0100, 0x0010, 0x0001,
                0x2000, 0x0200, 0x0020, 0x0002,
                0x3000, 0x0300, 0x0030, 0x0003,
        };*/

        int[] alphas = {0xe000, 0x0e00, 0x00e0, 0x000e,
                0xa000, 0x0a00, 0x00a0, 0x000a,
                0xb000, 0x0b00, 0x00b0, 0x000b,
                0x7000, 0x0700, 0x0070, 0x0007,
                0xd000, 0x0d00, 0x00d0, 0x000d,
                0xc000, 0x0c00, 0x00c0, 0x000c,
        };
        for (int alpha : alphas) {
            var searchResult = search(alpha, 6);

            writeToDisk(alpha, searchResult);
        }
    }

    private static void writeToDisk(int alpha, Map<Integer, Double> searchResult) throws IOException {
        var fileName = String.format("alpha_%s.json", Integer.toHexString(alpha));
        var file = new File(fileName);

        OBJECT_MAPPER.writeValue(file, searchResult);
    }

    public static Map<Integer, Double> search(int alpha, int r) {
        Map<Integer, Double> previous = new HashMap<>();
        previous.put(alpha, 1.0);

        var enc = encryptThemAll();

        double[] bounds = {0.1, 0.01, 0.003, 0.0003, 0.00005, 0.0005};

        Map<Integer, Double> current = new HashMap<>();

        for (int i = 0; i < r; i++) {
            for (Map.Entry<Integer, Double> pair : previous.entrySet()) {
                var probabilities = calculateProbabilities(pair.getKey(), enc);

                for (int x = 0; x < VECTORS_NUM; x++) {
                    var p = current.get(x);
                    if (p != null) {
                        current.put(x, current.get(x) + probabilities[x] * pair.getValue());
                    } else {
                        current.put(x, probabilities[x] * pair.getValue());
                    }
                }
            }

            previous.clear();

            for (Map.Entry<Integer, Double> pair : current.entrySet()) {
                if (pair.getValue() > bounds[i]) {
                    previous.put(pair.getKey(), pair.getValue());
                }
            }
        }

        return previous;
    }

    private static double[] calculateProbabilities(int alpha, int[] enc) {
        double[] frequencies = new double[VECTORS_NUM];

        for (int x = 0; x < VECTORS_NUM; x++) {
            frequencies[enc[x] ^ enc[x ^ alpha]]++;
        }

        double[] probabilities = new double[VECTORS_NUM];

        for (int x = 0; x < VECTORS_NUM; x++) {
            probabilities[x] = frequencies[x] / VECTORS_NUM;
        }

        return probabilities;
    }

    private static int[] encryptThemAll() {
        int[] encrypted = new int[VECTORS_NUM];

        for (int x = 0; x < VECTORS_NUM; x++) {
            encrypted[x] = HEYS.encryptBlock(x, DEFAULT_KEY);
        }

        return encrypted;
    }

}
