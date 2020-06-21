package ua.stepess.crypto.diff;

import ua.stepess.crypto.cipher.BlockCipher;
import ua.stepess.util.HeysCipherFactory;
import ua.stepess.util.IOUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DifferentialAttack {

    public static final int VECTORS_NUM = 0x10000;

    public static final BlockCipher HEYS = HeysCipherFactory.getDefaultHeysCipher();

    public static void main(String[] args) throws IOException {
        int[] alphas = {
                0x1000, 0x0100, 0x0010, 0x0001,
                0x2000, 0x0200, 0x0020, 0x0002,
                0x3000, 0x0300, 0x0030, 0x0003,
                0x4000, 0x0400, 0x0040, 0x0004,
                0x5000, 0x0500, 0x0050, 0x0005,
                0x6000, 0x0600, 0x0060, 0x0006,
                0x7000, 0x0700, 0x0070, 0x0007,
                0x8000, 0x0800, 0x0080, 0x0008,
                0x9000, 0x0900, 0x0090, 0x0009,
                0xa000, 0x0a00, 0x00a0, 0x000a,
                0xb000, 0x0b00, 0x00b0, 0x000b,
                0xc000, 0x0c00, 0x00c0, 0x000c,
                0xd000, 0x0d00, 0x00d0, 0x000d,
                0xe000, 0x0e00, 0x00e0, 0x000e,
                0xf000, 0x0f00, 0x00f0, 0x000f,
        };

        var fileName = "out/differentials.json";
        Map<Integer, Map<Integer, Double>> rawDifferentials;

        if (isDifferentialsCalculated(fileName)) {
            rawDifferentials = IOUtils.readDifferentialsFromFile(fileName);
        } else {
            rawDifferentials = calculateDifferentials(alphas);
            IOUtils.writeDifferentialsToDisk(fileName, rawDifferentials);
        }

        var differentials = rawDiffsToObj(rawDifferentials);

        System.out.println("Going to use the next differentials: ");
        var filteredDifferentials = filterDiffs(differentials);

        //int[] keys = CryptoUtils.generateKey();
        int[] keys =  {29345, 289, 57561, 51768, 46247, 8401, 0xace5};

        System.out.println();
        System.out.println("Key: " + Arrays.stream(keys).mapToObj(Integer::toHexString)
                .collect(Collectors.joining(" ")));

        System.out.println("Should recover: " + Integer.toHexString(keys[keys.length - 1]));

        /*for (Differential differential : filteredDifferentials) {
            attack(differential.a, differential.b, differential.probability, keys);
        }*/
    }

    public static List<Differential> filterDiffs(List<Differential> differentials) {
        return differentials.stream()
                .filter(p -> countNotEmptyTetras(p.b) == 4)
                .peek(System.out::println)
                .collect(Collectors.toList());
    }

    public static List<Differential> rawDiffsToObj(Map<Integer, Map<Integer, Double>> rawDifferentials) {
        return rawDifferentials.entrySet().stream()
                .filter(DifferentialAttack::isNotImpassibleDifferential)
                .flatMap(DifferentialAttack::toDifferentialStream)
                .collect(Collectors.toList());
    }

    private static boolean isNotImpassibleDifferential(Map.Entry<Integer, Map<Integer, Double>> e) {
        return e.getValue() != null && !e.getValue().isEmpty();
    }

    private static Stream<Differential> toDifferentialStream(Map.Entry<Integer, Map<Integer, Double>> rawDifferential) {
        return rawDifferential.getValue()
                .entrySet()
                .stream()
                .map(e -> Differential.of(rawDifferential.getKey(), e.getKey(), e.getValue()));
    }

    private static int countNotEmptyTetras(int x) {
        int count = 0;
        for (int i = 0; i < HeysCipherFactory.N; i++) {
            if (((x >>> (4 * i)) & 0xf) != 0) {
                count++;
            }
        }
        return count;
    }

    private static boolean isDifferentialsCalculated(String fileName) {
        return Files.exists(Path.of(fileName));
    }

    public static void attack(int alpha, int beta, double prob, int[] keys) {
        var plaintextCiphertextPairs = generatePlaintextCiphertextPairs(keys, prob, alpha);

        var lastKey = keys[keys.length - 1];

        var key = diffAtack(alpha, beta, plaintextCiphertextPairs);

        System.out.println("Am I right? " + (key == lastKey));
    }

    public static int  diffAtack(int alpha, int beta, Map<Integer, Integer> plaintextCiphertextPairs) {
        System.out.println();
        System.out.println("Start attack!");
        System.out.println("alpha = " + Integer.toHexString(alpha) + " beta = " + Integer.toHexString(beta));

        int[] keyScore = new int[VECTORS_NUM];

        int mostProbableKey = 0;
        int mostProbableKeyScore = 0;

        for (int k = 0; k < VECTORS_NUM; k++) {

            for (Map.Entry<Integer, Integer> p : plaintextCiphertextPairs.entrySet()) {
                int plaintext = p.getKey();
                int inputDifference = plaintext ^ alpha;

                int ciphertext = p.getValue();
                int inputDifferenceCiphertext = plaintextCiphertextPairs.get(inputDifference);

                int outputDifference =
                        HEYS.doDecryptionRound(ciphertext, k) ^ HEYS.doDecryptionRound(inputDifferenceCiphertext, k);

                if (outputDifference == beta) keyScore[k]++;
            }

            if (keyScore[k] > mostProbableKeyScore) {
                mostProbableKeyScore = keyScore[k];
                mostProbableKey = k;
            }

        }

        //System.out.println(Arrays.toString(Arrays.stream(keyScore).filter(i -> i != 0).toArray()));

        System.out.println();
        System.out.println("I'm not sure, but I guess it's: " + Integer.toHexString(mostProbableKey) + " key, it has score: "
                + mostProbableKeyScore);

        return mostProbableKey;
    }

    public static Map<Integer, Integer> generatePlaintextCiphertextPairs(int[] key, double probability, int a) {
        int size = (int) (12 / probability);
        Map<Integer, Integer> pairs = new HashMap<>();
        for (int i = 0; i < size; i++) {
            int x = ThreadLocalRandom.current().nextInt(VECTORS_NUM);
            pairs.put(x, HEYS.encryptBlock(x, key));
            pairs.put(x ^ a, HEYS.encryptBlock(x ^ a, key));
        }
        return pairs;
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

    public static Map<Integer, Double> search(int alpha, int r) {
        System.out.println("alpha = " + Integer.toHexString(alpha));

        Map<Integer, Double> previous = new HashMap<>();
        previous.put(alpha, 1.0);

        // the last one should be >> 0.00003051757
        double[] bounds = {0.001, 0.0008, 0.0005, 0.00001, 0.00005};

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
        }

        System.out.println("diffs = " + previous);

        return previous;
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
