package ua.stepess;

import ua.stepess.crypto.diff.DifferentialAttack;
import ua.stepess.util.CryptoUtils;
import ua.stepess.util.IOUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import static ua.stepess.crypto.diff.DifferentialAttack.VECTORS_NUM;

public class Differential {

    public static final String DIRECTORY = "tmp/diff";
    public static final String IN_ = "in_";
    private static final String OUT_ = "out_";

    public static void main(String[] args) throws IOException {
        var fileName = DIRECTORY + "/differentials.json";
        var rawDifferentials = IOUtils.readDifferentialsFromFile(fileName);
        var differentials = DifferentialAttack.rawDiffsToObj(rawDifferentials);
        var filteredDifferentials = DifferentialAttack.filterDiffs(differentials);

        samplePlaintexts(filteredDifferentials);
        
        for (ua.stepess.crypto.diff.Differential differential : filteredDifferentials) {
            var plaintextCiphertext = new HashMap<Integer, Integer>();

            var in = CryptoUtils.read(buildName(IN_, differential));
            var out = CryptoUtils.read(buildName(OUT_, differential));

            for (int i = 0; i < in.length; i++) {
                plaintextCiphertext.put(in[i], out[i]);
            }

            var key = DifferentialAttack.diffAtack(differential.getA(), differential.getB(), plaintextCiphertext);

            System.out.println("Found key:" + key);
        }
    }

    private static void samplePlaintexts(List<ua.stepess.crypto.diff.Differential> filteredDifferentials) {
        for (ua.stepess.crypto.diff.Differential differential : filteredDifferentials) {
            var plaintexts = CryptoUtils.generatePlaintextWithDifference(
                    (int) (8 * differential.getProbability() * VECTORS_NUM), differential.getA());
            IOUtils.writeToDisk(buildName(IN_, differential), plaintexts);
        }
    }

    private static String buildName(String prefix, ua.stepess.crypto.diff.Differential differential) {
        return DIRECTORY + prefix + Integer.toHexString(differential.getA())  + ".txt";
    }

}
