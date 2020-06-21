package ua.stepess;

import ua.stepess.crypto.linear.LinearAttack;
import ua.stepess.util.CryptoUtils;
import ua.stepess.util.IOUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class LinearLab {

    public static final String DIRECTORY = "tmp/linear";

    public static void main(String[] args) {
        var approximations = IOUtils.readApproximations(DIRECTORY + "/approximation.json")
                .stream()
                .filter(approximation -> approximation.level() > 5)
                .peek(System.out::println)
                .collect(Collectors.toList());

        var in = CryptoUtils.read(DIRECTORY + "/in.txt");
        var out = CryptoUtils.read(DIRECTORY + "/out.txt");

        Map<Integer, Integer> plaintextCiphertext = new HashMap<>();
        for (int i = 0; i < in.length; i++) {
            plaintextCiphertext.put(in[i], out[i]);
        }

        var key = LinearAttack.findMostProbableKeysForApproximations(plaintextCiphertext, approximations);
        System.out.println();
        System.out.println("Found key:" + key);
    }


}
