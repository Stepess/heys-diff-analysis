package ua.stepess.crypto.linear;

import ua.stepess.crypto.cipher.HeysCipher;
import ua.stepess.util.CryptoUtils;
import ua.stepess.util.HeysCipherFactory;
import ua.stepess.util.IOUtils;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

public class LinearAttack {

    public static final int VECTORS_NUM = 0x10000;

    private static final int LAST_KEYS_NUMBER = 16;

    private static final int KEYS_NUMBER = 100;

    private static final HeysCipher CIPHER = (HeysCipher) HeysCipherFactory.getDefaultHeysCipher();

    private static final double[][] S_BOX_LP = computeLinearPotentials();

    public static void main(String[] args) {
        generateApproximations();

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

        Map<Integer, Integer> recoverFirst = recoverFirst(data, approximations, keys[0]);

        recoverFirst.forEach((k, c) -> System.out.println("Key = " + Integer.toHexString(k) + " count = " + c));
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
                System.out.println("a = " + Integer.toHexString(a));
                pairs.addAll(search(a,5));
            }
        }
        System.out.println("Approximations:");
        pairs.forEach(System.out::println);
        System.out.println("Total size = " + pairs.size());

        IOUtils.writeToDisk("out/approximation.json", pairs);
    }

    public static List<Approximation> search(int alpha, int r) {
        System.out.println("alpha = " + Integer.toHexString(alpha));

        Map<Integer, Double> previous = new HashMap<>();
        previous.put(alpha, 1.0);

        // the last one should be >> 0.00003051757
        double[] bounds = {0.001, 0.0008, 0.0005, 0.00001, 0.00005};

        Map<Integer, Double> current = new HashMap<>();

        for (int i = 0; i < r; i++) {

            current.clear();

            for (Map.Entry<Integer, Double> g : previous.entrySet()) {
                var probabilities = differenceProbabilityDistribution(g.getKey());

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

        return previous.entrySet().stream()
                .map(e -> Approximation.of(alpha, e.getKey(), e.getValue()))
                .collect(Collectors.toList());
    }
    
    public static Map<Integer, Integer> recoverFirst(Map<Integer, Integer> data, Collection<Approximation> pairs, int rightKey) {
        Map<Integer, Integer> counts = new HashMap<>();
        for (Approximation approximation : pairs) {
            System.out.println("Approximation: " + approximation);
            for (Integer key : recoverFirst(data, approximation.a, approximation.b)) {
                counts.put(key, counts.getOrDefault(key, 0) + 1);
            }
            head(counts, LAST_KEYS_NUMBER).forEach((k,v) ->
                    System.out.println("Key: " + Integer.toHexString(k) + " count: " + v));

            System.out.println();
            System.out.println();
            System.out.println();

            System.out.println("Contains key: " + counts.containsKey(rightKey));
            System.out.println("key count: " + counts.get(rightKey));

            System.out.println();
            System.out.println();
            System.out.println();
            System.out.println();
        }
        return head(counts, LAST_KEYS_NUMBER);
    }

    public static Map<Integer, Integer> recoverFirst(Map<Integer, Integer> data, Collection<Approximation> pairs) {
        Map<Integer, Integer> counts = new HashMap<>();
        for (Approximation approximation : pairs) {
            System.out.println("Approximation: " + approximation);
            for (Integer key : recoverFirst(data, approximation.a, approximation.b)) {
                counts.put(key, counts.getOrDefault(key, 0) + 1);
            }
            head(counts, LAST_KEYS_NUMBER).forEach((k,v) ->
                    System.out.println("Key: " + Integer.toHexString(k) + " count: " + v));
            System.out.println();
            System.out.println();
            System.out.println();
            System.out.println();
        }
        return head(counts, LAST_KEYS_NUMBER);
    }

    public static Collection<Integer> recoverFirst(Map<Integer, Integer> data, int a, int b) {
        Map<Integer, Integer> counts = new HashMap<>(1 << 16);
        int[][] dataArray = toArray(data);
        for (int k = 0; k < (1 << HeysCipherFactory.BLOCK_SIZE); k++) {
            int count = 0;
            for (int t = 0; t < dataArray.length; t++) {
                int x = CIPHER.doEncryptionRound(dataArray[t][0], k);
                count += dot(a, x) ^ dot(b, dataArray[t][1]);
            }
            count = Math.max(count, (1 << HeysCipherFactory.BLOCK_SIZE) - count);
            counts.put(k, Math.abs(count));
        }
        return head(counts, KEYS_NUMBER).keySet();
    }

    public static double[] differenceProbabilityDistribution(int a) {
        double[] distribution = new double[1 << HeysCipherFactory.BLOCK_SIZE];
        for (int b = 0; b < distribution.length; b++) {
            distribution[b] = getLp(a, b);
        }
        return distribution;
    }

    private static double getLp(int a, int b) {
        double p = 1.0;
        b = CIPHER.shuffle(b);
        for (int i = 0; i < HeysCipherFactory.N; i++) {
            int aPrime = (a >>> (4 * i)) & 0xF;
            int bPrime = (b >>> (4 * i)) & 0xF;
            p *= S_BOX_LP[aPrime][bPrime];
        }
        return p;
    }

    public static int dot(int x, int y) {
        int z = x & y;
        z = z ^ (z >>> 8);
        z = z ^ (z >>> 4);
        z = z ^ (z >>> 2);
        return (z ^ (z >>> 1)) & 0x1;
    }

    private static double[][] computeLinearPotentials() {
        double[][] lp = new double[1 << HeysCipherFactory.N][1 << HeysCipherFactory.N];
        for (int a = 0; a < (1 << HeysCipherFactory.N); a++) {
            for (int b = 0; b < (1 << HeysCipherFactory.N); b++) {
                double val = 0;
                for (int x = 0; x < (1 << HeysCipherFactory.N); x++) {
                    int degree = dot(a, x) ^ dot(b, CIPHER.substitute(x));
                    if (degree == 1) {
                        val--;
                    } else {
                        val++;
                    }
                }
                lp[a][b] = Math.pow(val / (1 << HeysCipherFactory.N), 2);
            }
        }
        return lp;
    }

    private static int[][] toArray(Map<Integer, Integer> data) {
        int[][] array = new int[data.size()][2];
        int index = 0;
        for (Map.Entry<Integer, Integer> entry : data.entrySet()) {
            array[index][0] = entry.getKey();
            array[index][1] = entry.getValue();
            index++;
        }
        return array;
    }

    public static Map<Integer, Integer> head(Map<Integer, Integer> data, int size) {
        return data.entrySet()
                .stream()
                .sorted(Comparator.comparingInt(Map.Entry<Integer, Integer>::getValue).reversed())
                .limit(size)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
    
}
