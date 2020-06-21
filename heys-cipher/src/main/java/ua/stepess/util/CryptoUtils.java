package ua.stepess.util;

import java.util.concurrent.ThreadLocalRandom;

import static ua.stepess.crypto.diff.DifferentialAttack.VECTORS_NUM;

public class CryptoUtils {

    public static int[] generateKey() {
        var keys = new int[7];

        for (int i = 0; i < keys.length; i++) {
            keys[i] = ThreadLocalRandom.current().nextInt(VECTORS_NUM);
        }

        return keys;
    }
}
