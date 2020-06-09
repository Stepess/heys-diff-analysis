package ua.stepess.crypto.diff;

import com.fasterxml.jackson.databind.ObjectMapper;
import ua.stepess.crypto.cipher.BlockCipher;
import ua.stepess.util.HeysCipherFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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

        /*int[] alphas = {0xe000, 0x0e00, 0x00e0, 0x000e,
                0xa000, 0x0a00, 0x00a0, 0x000a,
                0xb000, 0x0b00, 0x00b0, 0x000b,
                0x7000, 0x0700, 0x0070, 0x0007,
                0xd000, 0x0d00, 0x00d0, 0x000d,
                0xc000, 0x0c00, 0x00c0, 0x000c,
        };*/

        var differentials = new HashMap<Integer, List<Integer>>();

        int[] alphas = {0x0100};
        for (int alpha : alphas) {
            var searchResult = search(alpha, 6);

            var diffs = new ArrayList<>(searchResult.keySet());
            differentials.put(alpha, diffs);

            writeToDisk(alpha, searchResult);
        }

        /*var ciphertext = new HashMap<Integer, Integer>();

        for (int x = 0; x < VECTORS_NUM; x++) {
            ciphertext.put(x, HEYS.encryptBlock(x, DEFAULT_KEY));
        }

        for (Map.Entry<Integer, List<Integer>> diff : differentials.entrySet()) {
            attack(diff.getKey(), diff.getValue(), ciphertext, DEFAULT_KEY);
        }*/

    }

    private static void writeToDisk(int alpha, Map<Integer, Double> searchResult) throws IOException {
        var fileName = String.format("alpha_%s.json", Integer.toHexString(alpha));
        var file = new File(fileName);

        OBJECT_MAPPER.writeValue(file, searchResult);
    }

    public static Map<Integer, Double> search(int alpha, int r) {
        Map<Integer, Double> previous = new HashMap<>();
        previous.put(alpha, 1.0);

        // the last one should be >> 0.00003051757
        double[] bounds = {0.0001, 0.00000013, 0.00000000006, 0.00000000000007, 0.00000000000000002, 0.0005};

        Map<Integer, Double> current = new HashMap<>();

        for (int i = 0; i < r; i++) {

            current.clear();

            for (Map.Entry<Integer, Double> g : previous.entrySet()) {
                var probabilities = calculateProbabilities(g.getKey());

                for (int x = 0; x < VECTORS_NUM; x++) {
                    var p = current.get(x);
                    if (p != null) {
                        current.put(x, p + probabilities[x] * g.getValue());
                    } else {
                        current.put(x, probabilities[x] * g.getValue());
                    }
                }
            }

            previous.clear();

            for (Map.Entry<Integer, Double> pair : current.entrySet()) {
                if (pair.getValue() > bounds[i]) {
                    previous.put(pair.getKey(), pair.getValue());
                }
            }

            System.out.println("Round #" + i);
            System.out.println();
            System.out.println("Survived : " + previous);
        }

        return previous;
    }

    public static void attack(int alpha, List<Integer> betas, Map<Integer, Integer> ciphertexts, String key) {
        int lastKey = Integer.valueOf(key.substring(24), 16);

        for (int beta : betas) {
            int count = 0;
            int mostProbableKey = 0;

            for (int k = 0; k < VECTORS_NUM; k++) {
                int currentKeyScore = 0;

                for (int x = 0; x < VECTORS_NUM; x++) {
                    if ((HEYS.doDecryptionRound(ciphertexts.get(x), k) ^
                            HEYS.doDecryptionRound(ciphertexts.get(x ^ alpha), k)) == beta)
                        currentKeyScore++;
                }

                if (currentKeyScore > count) {
                    count = currentKeyScore;
                    mostProbableKey = k;
                }

            }

            System.out.println(count);
            System.out.println(mostProbableKey == lastKey);
        }
    }

    private static double[] calculateProbabilities(int alpha) {
        double[] frequencies = new double[VECTORS_NUM];

        // this cipher is Markov's, so differential probabilities doesn't depends on input
        for (int k = 0; k < VECTORS_NUM; k++) {
            frequencies[HEYS.doEncryptionRound(0, k) ^
                    HEYS.doDecryptionRound(alpha, k)]++;
        }


        double[] probabilities = new double[VECTORS_NUM];

        for (int x = 0; x < VECTORS_NUM; x++) {
            probabilities[x] = frequencies[x] / VECTORS_NUM;
        }

        return probabilities;
    }

}
