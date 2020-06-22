package ua.stepess.util;

import ua.stepess.crypto.cipher.BlockCipher;
import ua.stepess.crypto.cipher.HeysCipher;
import ua.stepess.crypto.cipher.HeysCipherFast;

public class HeysCipherFactory {

    public static final int NUM_OF_ROUNDS = 6;
    public static final int N = 4;
    public static final int BLOCK_SIZE = N*N;

    public static BlockCipher getDefaultHeysCipher() {
        return new HeysCipherFast(N, NUM_OF_ROUNDS, SBoxFactory.getDefaultSBox());
    }

}
