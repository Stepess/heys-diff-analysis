package ua.stepess;

import ua.stepess.crypto.SBox;

import java.util.Arrays;

public class AppRunner {

    public static final String[] S_BOX_SCHEMA =
            {"8", "0", "C", "4", "9", "6", "7", "B", "2", "3", "1", "F", "5", "E", "A", "D"};

    public static void main(String[] args) {
        var sBoxSubstitution = Arrays.stream(S_BOX_SCHEMA)
                .mapToInt(c -> Integer.parseInt(c, 16))
                .toArray();


        var sBox = new SBox(sBoxSubstitution);


    }

}
