package ua.stepess.util;

import ua.stepess.crypto.SBox;

import java.util.Arrays;

public class SBoxFactory {

    public static final String[] S_BOX_SCHEMA =
            {"8", "0", "C", "4", "9", "6", "7", "B", "2", "3", "1", "F", "5", "E", "A", "D"};

    public static SBox getDefaultSBox() {
        int[] intSchema = Arrays.stream(S_BOX_SCHEMA)
                .mapToInt(c -> Integer.parseInt(c, 16))
                .toArray();

        return new SBox(intSchema);
    }

}
