package ua.stepess;

import ua.stepess.crypto.cipher.BlockCipher;
import ua.stepess.util.HeysCipherFactory;

import java.util.concurrent.ThreadLocalRandom;

public class Main {

    public static void main(String[] args) {
        var heysCipher = new HeysCipher();
        var heysCipher1 = HeysCipherFactory.getDefaultHeysCipher();

        testFull(heysCipher, heysCipher1);
    }

    private static void testFull(HeysCipher heysCipher, BlockCipher heysCipher1) {
        for (int i = 0; i < 100_000_0; i++) {
            var x = ThreadLocalRandom.current().nextInt(0x10000);
            var k = new int[]{29345, 289, 57561, 51768, 46247, 8401, 0xace5};
            var rk = new int[]{0xace5, 8401, 46247, 51768, 57561, 289, 29345};
            var alex = heysCipher.decrypt(x, rk);
            var mine = heysCipher1.decryptBlock(x, k);

            System.out.println("Equals? " + (alex == mine));
            if (alex != mine) {
                System.out.println("x = " + x);
                System.out.println("k = " + k);
                System.out.println("alex's = " + alex);
                System.out.println("mine's = " + mine);
                return;
            }
        }
    }

    private static void decryptRoundTest(HeysCipher heysCipher, BlockCipher heysCipher1) {
        for (int i = 0; i < 100_000_0; i++) {
            var x = ThreadLocalRandom.current().nextInt(0x10000);
            var k = ThreadLocalRandom.current().nextInt(0x10000);
            var alex = heysCipher.encryptRound(x, k);
            var mine = heysCipher1.doEncryptionRound(x, k);

            System.out.println("Equals? " + (alex == mine));
            if (alex != mine) {
                System.out.println("x = " + x);
                System.out.println("k = " + k);
                System.out.println("alex's = " + alex);
                System.out.println("mine's = " + mine);
            }
        }
    }


}
