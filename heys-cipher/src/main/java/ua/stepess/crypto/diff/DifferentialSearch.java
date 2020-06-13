package ua.stepess.crypto.diff;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ua.stepess.crypto.cipher.BlockCipher;
import ua.stepess.util.HeysCipherFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

public class DifferentialSearch {

    public static final int VECTORS_NUM = 0x10000;

    public static final BlockCipher HEYS = HeysCipherFactory.getDefaultHeysCipher();
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static final String DEFAULT_KEY = "a1722101d9e038caa7b4d120c18b";

    public static void main(String[] args) throws IOException {
        int[] alphas = {0xf000, 0x0f00, 0x00f0, 0x000f,
                0x1000, 0x0100, 0x0010, 0x0001,
                0x2000, 0x0200, 0x0020, 0x0002,
                0x3000, 0x0300, 0x0030, 0x0003,
                0xe000, 0x0e00, 0x00e0, 0x000e,
                0xa000, 0x0a00, 0x00a0, 0x000a,
                0xb000, 0x0b00, 0x00b0, 0x000b,
                0x7000, 0x0700, 0x0070, 0x0007,
                0xd000, 0x0d00, 0x00d0, 0x000d,
                0xc000, 0x0c00, 0x00c0, 0x000c,
        };

        var fileName = "differentials.json";
        Map<Integer, Map<Integer, Double>> differentials;

        if (isDifferentialsCalculated(fileName)) {
            differentials = readDifferentialsFromFile(fileName);
        } else {
            differentials = calculateDifferentials(alphas);

            writeToDisk(differentials);
        }

        // cleanup
        differentials.entrySet().removeIf(e -> e.getValue() == null || e.getValue().isEmpty());

        var ciphertext = new HashMap<Integer, Integer>();

        for (int x = 0; x < VECTORS_NUM; x++) {
            ciphertext.put(x, HEYS.encryptBlock(x, DEFAULT_KEY));
        }

        Map<Integer, Set<Integer>> convertedDifferentials = differentials.entrySet()
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().keySet()));



        /*for (Map.Entry<Integer, Set<Integer>> diff : convertedDifferentials.entrySet()) {
            attack(diff.getKey(), diff.getValue(), ciphertext, DEFAULT_KEY);
        }*/

        var diff = convertedDifferentials.get(3);
        attack(3, diff, ciphertext, DEFAULT_KEY);

    }

    private static boolean isDifferentialsCalculated(String fileName) {
        return Files.exists(Path.of(fileName));
    }

    private static Map<Integer, Map<Integer, Double>> calculateDifferentials(int[] alphas) {
        Map<Integer, Map<Integer, Double>> differentials;
        differentials = new HashMap<>();

        for (int alpha : alphas) {
            var searchResult = search(alpha, 5);

            differentials.put(alpha, searchResult);
        }
        return differentials;
    }

    private static Map<Integer, Map<Integer, Double>> readDifferentialsFromFile(String fileName) throws IOException {
        var srcFile = new File(fileName);
        return OBJECT_MAPPER.readValue(srcFile, new TypeReference<>() {
        });
    }

    private static void writeToDisk(Map<Integer, Map<Integer, Double>> searchResult) throws IOException {
        var file = new File("differentials.json");

        OBJECT_MAPPER.writeValue(file, searchResult);
    }

    public static Map<Integer, Double> search(int alpha, int r) {
        Map<Integer, Double> previous = new HashMap<>();
        previous.put(alpha, 1.0);

        // the last one should be >> 0.00003051757
        double[] bounds = {0.001, 0.00013, 0.0009, 0.00007, 0.001};

        Map<Integer, Double> current = new HashMap<>();

        for (int i = 0; i < r; i++) {

            current.clear();

            for (Map.Entry<Integer, Double> g : previous.entrySet()) {
                var probabilities = calculateProbabilities(g.getKey());

                for (int x = 0; x < VECTORS_NUM; x++) {
                    current.put(x, current.getOrDefault(x, 0.0) + probabilities[x] * g.getValue());
                }
            }

            previous.clear();

            for (Map.Entry<Integer, Double> pair : current.entrySet()) {
                if (pair.getValue() > bounds[i]) {
                    previous.put(pair.getKey(), pair.getValue());
                }
            }

            /*System.out.println();
            System.out.println("Round #" + i);
            System.out.println();
            System.out.println("Survived : " + previous);*/
        }

        System.out.println("alpha = " + alpha);
        System.out.println("diffs = " + previous);

        return previous;
    }

    public static void attack(int alpha, Collection<Integer> betas, Map<Integer, Integer> ciphertexts, String key) {
        int lastKey = Integer.valueOf(key.substring(24), 16);

        int[] keyScore = new int[VECTORS_NUM];

        int mostProbableKey = 0;
        int mostProbableKeyScore = 0;

        for (int beta : betas) {


            for (int k = 0; k < VECTORS_NUM; k++) {


                for (Map.Entry<Integer, Integer> c : ciphertexts.entrySet()) {
                    if (
                            (
                                    HEYS.doDecryptionRound(c.getValue(), k) ^
                                            HEYS.doDecryptionRound(ciphertexts.get(c.getKey() ^ alpha), k)
                            ) == beta) {
                        keyScore[k]++;
                    }
                }

                if (keyScore[k] > mostProbableKey) {
                    mostProbableKeyScore = keyScore[k];
                    mostProbableKey = k;
                }

            }

        }

        System.out.println(Arrays.toString(Arrays.stream(keyScore).filter(i -> i != 0).toArray()));

        System.out.println();
        System.out.println(mostProbableKey + " " + mostProbableKeyScore);
        System.out.println(mostProbableKey == lastKey);
    }

    private static double[] calculateProbabilities(int alpha) {
        double[] frequencies = new double[VECTORS_NUM];

        // this cipher is Markov's, so differential probabilities doesn't depends on input
        for (int k = 0; k < VECTORS_NUM; k++) {
            frequencies[HEYS.doEncryptionRound(0, k) ^ HEYS.doEncryptionRound(alpha, k)]++;
        }

        double[] probabilities = new double[VECTORS_NUM];

        for (int x = 0; x < VECTORS_NUM; x++) {
            probabilities[x] = frequencies[x] / VECTORS_NUM;
        }

        return probabilities;
    }

}
