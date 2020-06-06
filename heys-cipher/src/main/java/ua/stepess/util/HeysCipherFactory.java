package ua.stepess.util;

import ua.stepess.crypto.cipher.BlockCipher;
import ua.stepess.crypto.cipher.HeysCipher;

public class HeysCipherFactory {

    public static BlockCipher getDefaultHeysCipher() {
        return new HeysCipher(4, 6, SBoxFactory.getDefaultSBox());
    }

}
