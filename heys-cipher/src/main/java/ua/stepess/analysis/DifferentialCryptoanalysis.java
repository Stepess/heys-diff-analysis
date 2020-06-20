package ua.stepess.analysis;

import ua.stepess.crypto.cipher.BlockCipher;
import ua.stepess.util.HeysCipherFactory;

import java.util.Map;

public final class DifferentialCryptoanalysis {
    private static final BlockCipher CIPHER = HeysCipherFactory.getDefaultHeysCipher();

    public static void main(String[] args) {

        var key = "a1722101d9e038caa7b4d120c18b";

        int block = 32300;
        System.out.println(Integer.toHexString(CIPHER.doEncryptionRound(block, 112)));
        System.out.println(Integer.toHexString(CIPHER.doDecryptionRound(block, 112)));
        //int[] keys = {1, 2, 3, 4, 5, 6, 7};
        int[] keys = {29345, 289, 57561, 51768, 46247, 8401, 35777};
        System.out.println(Integer.toHexString(CIPHER.encryptBlock(block, keys)));
        //System.out.println(Integer.toHexString(CIPHER.encryptBlock(block, key)));
        System.out.println(CIPHER.decryptBlock(CIPHER.encryptBlock(block, keys), keys));

    }

    private static int[] reverse(int[] arr) {
        int[] ints = new int[arr.length];
        for (int i = 0; i < arr.length; i++) {
            ints[arr.length - i - 1] = arr[i];
        }
        return ints;
    }

    private DifferentialCryptoanalysis() {}

    public static int recoverLast(Map<Integer, Integer> data, int a, int b) {
        int recovered = 0;
        int count = -1;
        for (int k = 0; k < (1 << HeysCipherFactory.BLOCK_SIZE); k++) {
            int keyCount = 0;
            for (Map.Entry<Integer, Integer> entry : data.entrySet()) {
                int x = entry.getKey();
                int xa = x ^ a;

                int y = entry.getValue();
                int ya = data.get(xa);

                int difference = CIPHER.doDecryptionRound(y, k) ^ CIPHER.doDecryptionRound(ya, k);
                keyCount += (difference == b ? 1 : 0);
            }
            if (keyCount > count) {
                recovered = k;
                count = keyCount;
            }
        }

        return recovered;
    }

    public static int differentialSize(int x) {
        int size = 0;
        for (int i = 0; i < HeysCipherFactory.N; i++) {
            if (((x >>> (4 * i)) & 0xF) != 0) {
                size++;
            }
        }
        return size;
    }

    public static double[] differenceProbabilityDistribution(int a) {
        double[] distribution = new double[1 << HeysCipherFactory.BLOCK_SIZE];
        for (int x = 0; x < distribution.length; x++) {
            distribution[CIPHER.doEncryptionRound(x, 0) ^ CIPHER.doEncryptionRound(x ^ a, 0)]++;
        }
        for (int i = 0; i < distribution.length; i++) {
            distribution[i] /= distribution.length;
        }
        return distribution;
    }

}
