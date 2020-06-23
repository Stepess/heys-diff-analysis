package ua.stepess.crypto.linear;

import ua.stepess.crypto.cipher.HeysCipherFast;
import ua.stepess.util.CryptoUtils;
import ua.stepess.util.HeysCipherFactory;
import ua.stepess.util.IOUtils;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

public class LinearAttack {

    public static final int VECTORS_NUM = 0x10000;

    private static final int KEY_LIMIT = 10;

    private static final int PER_APPROXIMATION_KEY_LIMIT = 100;

    private static final HeysCipherFast CIPHER = (HeysCipherFast) HeysCipherFactory.getFastHeysCipher();

    public static void main(String[] args) {
        generateApproximations();

        if (true) return;
        int[] keys = CryptoUtils.generateKey();

        System.out.println("Should be: " + Integer.toHexString(keys[0]));
        Map<Integer, Integer> data = generatePlaintextCiphertextPairs(keys, 25000);

        System.out.println("Size = " + data.size());

        var approximations = IOUtils.readApproximations("out/approximation.json")
                .stream()
                .filter(approximation -> approximation.level() > 5)
                .peek(System.out::println)
                .collect(Collectors.toList());

        System.out.println("A = " + approximations.size());

        var firstKeys = findMostProbableKeysForApproximations(data, approximations, keys[0]);

        firstKeys.forEach((k, c) -> System.out.println("Key = " + Integer.toHexString(k) + " count = " + c));
    }

    public static Map<Integer, Integer> generatePlaintextCiphertextPairs(int[] key, double probability) {
        int size = (int) (12 / probability);
        Map<Integer, Integer> pairs = new HashMap<>();
        for (int i = 0; i < size; i++) {
            int x = ThreadLocalRandom.current().nextInt(VECTORS_NUM);
            pairs.put(x, CIPHER.encryptBlock(x, key));
        }
        return pairs;
    }

    private static void generateApproximations() {
        Collection<Approximation> pairs = new ArrayList<>();
        for (int i = 0; i < HeysCipherFactory.N; i++) {
            for (int j = 1; j < (1 << HeysCipherFactory.N); j++) {
                int a = j << (4 * i);
                pairs.addAll(search(a, 5));
            }
        }
        System.out.println("Approximations:");
        pairs.forEach(System.out::println);
        System.out.println("Total size = " + pairs.size());

        IOUtils.writeToDiskAsJson("tmp/linear/approximation.json", pairs);
    }

    public static List<Approximation> search(int alpha, int r) {
        System.out.println("alpha = " + Integer.toHexString(alpha));

        Map<Integer, Double> previous = new HashMap<>();
        previous.put(alpha, 1.0);

        double[] bounds = {0.00015, 0.00015, 0.00015, 0.00015, 0.00015};

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

        System.out.println("approximations = " + previous);

        return previous.entrySet().stream()
                .map(e -> Approximation.of(alpha, e.getKey(), e.getValue()))
                .collect(Collectors.toList());
    }

    public static Map<Integer, Integer> findMostProbableKeysForApproximations(Map<Integer, Integer> plaintextCiphertextMap, List<Approximation> approximations) {
        Map<Integer, Integer> keyScore = new HashMap<>();
        for (Approximation approximation : approximations) {
            System.out.println("Approximation: " + approximation);
            var mostProbableKeysForApproximation =
                    findMostProbableKeysForApproximation(plaintextCiphertextMap, approximation.a, approximation.b);
            mostProbableKeysForApproximation.forEach(key ->
                    keyScore.put(key, keyScore.getOrDefault(key, 0) + 1));

            findFirst(keyScore, KEY_LIMIT).forEach((k, v) ->
                    System.out.println("Key: " + Integer.toHexString(k) + " count: " + v));
        }
        return findFirst(keyScore, KEY_LIMIT);
    }


    public static Map<Integer, Integer> findMostProbableKeysForApproximations(Map<Integer, Integer> plaintextCiphertextMap, List<Approximation> approximations, int rightKey) {
        Map<Integer, Integer> keyScore = new HashMap<>();
        for (Approximation approximation : approximations) {
            System.out.println("Approximation: " + approximation);
            var mostProbableKeysForApproximation =
                    findMostProbableKeysForApproximation(plaintextCiphertextMap, approximation.a, approximation.b);
            mostProbableKeysForApproximation.forEach(key ->
                    keyScore.put(key, keyScore.getOrDefault(key, 0) + 1));

            findFirst(keyScore, KEY_LIMIT).forEach((k, v) ->
                    System.out.println("Key: " + Integer.toHexString(k) + " count: " + v));

            System.out.println();
            System.out.println();
            System.out.println();

            System.out.println("Contains key: " + keyScore.containsKey(rightKey));
            System.out.println("key count: " + keyScore.get(rightKey));

            System.out.println();
            System.out.println();
            System.out.println();
            System.out.println();
        }
        return findFirst(keyScore, KEY_LIMIT);
    }

    public static Set<Integer> findMostProbableKeysForApproximation(Map<Integer, Integer> plaintextCiphertext, int a, int b) {
        Map<Integer, Integer> counts = new HashMap<>(VECTORS_NUM);
        for (int k = 0; k < VECTORS_NUM; k++) {
            int count = 0;
            for (Map.Entry<Integer, Integer> p : plaintextCiphertext.entrySet()) {
                int x = CIPHER.doEncryptionRound(p.getKey(), k);
                count += scalarProduct(a, x) ^ scalarProduct(b, p.getValue());
            }
            count = Math.max(count, VECTORS_NUM - count);
            counts.put(k, Math.abs(count));
        }
        return findFirst(counts, PER_APPROXIMATION_KEY_LIMIT).keySet();
    }

    public static double[] calculateProbabilities(int a) {
        var linearPotentials = computeLinearPotentials();
        var distribution = new double[VECTORS_NUM];
        for (int b = 0; b < distribution.length; b++) {
            distribution[b] = 1.0;
            b = CIPHER.permutation(b);
            //b = CIPHER.shuffle(b);
            for (int i = 0; i < HeysCipherFactory.N; i++) {
                int aPrime = (a >>> (4 * i)) & 0xF;
                int bPrime = (b >>> (4 * i)) & 0xF;
                distribution[b] *= linearPotentials[aPrime][bPrime];
            }
        }
        return distribution;
    }

    public static int scalarProduct(int x, int y) {
        int res = 0;
        for (int i = 0; i < HeysCipherFactory.BLOCK_SIZE; i++) {
            res ^= ((x >>> i) & (y >>> i));
        }
        return res & 0x1;
    }

    private static double[][] computeLinearPotentials() {
        double[][] lp = new double[16][16];
        for (int a = 0; a < 16; a++) {
            for (int b = 0; b < 16; b++) {
                double value = 0;
                for (int x = 0; x < 16; x++) {
                    int degree = scalarProduct(a, x) ^ scalarProduct(b, CIPHER.substitution(x));
                    value += degree == 1 ? -1 : 1;
                }
                lp[a][b] = Math.pow(value / 16, 2);
            }
        }
        return lp;
    }

    public static Map<Integer, Integer> findFirst(Map<Integer, Integer> data, int size) {
        return data.entrySet()
                .stream()
                .sorted(Comparator.comparingInt(Map.Entry<Integer, Integer>::getValue).reversed())
                .limit(size)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

}
