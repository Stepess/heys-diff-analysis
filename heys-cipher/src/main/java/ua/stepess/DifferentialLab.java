package ua.stepess;

import ua.stepess.crypto.diff.Differential;
import ua.stepess.crypto.diff.DifferentialAttack;
import ua.stepess.util.CryptoUtils;
import ua.stepess.util.IOUtils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.List;

import static ua.stepess.crypto.diff.DifferentialAttack.VECTORS_NUM;

public class DifferentialLab {

    public static final String DIRECTORY = "tmp/diff";
    public static final String IN_ = "/in_";
    private static final String OUT_ = "/out_";
    public static final String HEYS_UTIL_PATH = "/home/stepan/IdeaProjects/heys-diff-analysis/heys.bin";

    public static void main(String[] args) throws IOException {
        var fileName = DIRECTORY + "/differentials.json";
        var rawDifferentials = IOUtils.readDifferentialsFromFile(fileName);
        var differentials = DifferentialAttack.rawDiffsToObj(rawDifferentials);
        var filteredDifferentials = DifferentialAttack.filterDiffs(differentials);

        prepareAttackMaterial(filteredDifferentials);

        for (Differential differential : filteredDifferentials) {
            var plaintextCiphertext = new HashMap<Integer, Integer>();

            var in = CryptoUtils.read(buildName(IN_, differential));
            var out = CryptoUtils.read(buildName(OUT_, differential));

            for (int i = 0; i < in.length; i++) {
                plaintextCiphertext.put(in[i], out[i]);
            }

            System.out.println("Input size: " + plaintextCiphertext.size());

            var key = DifferentialAttack.diffAtack(differential.getA(), differential.getB(), plaintextCiphertext);

            System.out.println("Found key:" + Integer.toHexString(key));
        }

    }

    private static void prepareAttackMaterial(List<Differential> differentials) {
        samplePlaintexts(differentials);
        encryptPlaintext(differentials);
    }

    private static void encryptPlaintext(List<Differential> differentials) {
        for (Differential differential : differentials) {
            var processBuilder = new ProcessBuilder(HEYS_UTIL_PATH, "e", "2",
                    buildName(IN_, differential), buildName(OUT_, differential));
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
    }

    private static void samplePlaintexts(List<Differential> filteredDifferentials) {
        for (Differential differential : filteredDifferentials) {
            var plaintexts = CryptoUtils.generatePlaintextWithDifference(
                    (int) (8 * 16 * differential.getProbability() * VECTORS_NUM), differential.getA());
            CryptoUtils.writeAsBinary(plaintexts, buildName(IN_, differential));
        }
    }

    private static String buildName(String prefix, Differential differential) {
        return DIRECTORY + prefix + Integer.toHexString(differential.getA());
    }

}
