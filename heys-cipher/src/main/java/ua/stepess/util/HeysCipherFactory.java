package ua.stepess.util;

import ua.stepess.crypto.cipher.BlockCipher;
import ua.stepess.crypto.cipher.HeysCipher;

public class HeysCipherFactory {

    public static final int NUM_OF_ROUNDS = 6;
    public static final int N = 4;
    public static final int BLOCK_SIZE = N*N;

    public static BlockCipher getDefaultHeysCipher() {
        return new HeysCipher(N, NUM_OF_ROUNDS, SBoxFactory.getDefaultSBox());
    }

}
