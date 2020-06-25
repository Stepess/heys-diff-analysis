package ua.stepess;

import ua.stepess.crypto.linear.LinearAttack;
import ua.stepess.util.CryptoUtils;
import ua.stepess.util.IOUtils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class LinearLab {

    public static final String HEYS_UTIL_PATH = "/home/stepan/IdeaProjects/heys-diff-analysis/heys.bin";

    public static final String DIRECTORY = "tmp/linear";

    public static void main(String[] args) {
        var approximations = IOUtils.readApproximations(DIRECTORY + "/approximation.json")
                .stream()
                .peek(System.out::println)
                .collect(Collectors.toList());

        //samplePlaintexts();
        //prepareAttackMaterial();

        var in = CryptoUtils.read(DIRECTORY + "/in");
        var out = CryptoUtils.read(DIRECTORY + "/out");

        Map<Integer, Integer> plaintextCiphertext = new HashMap<>();
        for (int i = 0; i < in.length; i++) {
            plaintextCiphertext.put(in[i], out[i]);
        }

        System.out.println();
        System.out.println("Attack material size: " + plaintextCiphertext.size());
        System.out.println();

        var key = LinearAttack.findMostProbableKeysForApproximations(plaintextCiphertext, approximations);
        System.out.println();
        System.out.println("Found key:" + key);
    }

    private static void prepareAttackMaterial() {
        samplePlaintexts();
        encryptPlaintext();
    }

    private static void encryptPlaintext() {
        var processBuilder = new ProcessBuilder(HEYS_UTIL_PATH, "e", "2",
                DIRECTORY + "/in", DIRECTORY + "/out");
        Process process;
        try {
            process = processBuilder.start();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        // hack to bypass enter at the end
        try {
            Thread.sleep(5_000L);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        process.destroy();
    }

    private static void samplePlaintexts() {
        //(int) (1.0 / 0.00015)
        var plaintexts = CryptoUtils.generatePlaintext(25000);
        CryptoUtils.writeAsBinary(plaintexts, DIRECTORY + "/in");
    }


}
