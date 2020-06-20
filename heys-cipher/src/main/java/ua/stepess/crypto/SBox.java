package ua.stepess.crypto;

import static java.util.Arrays.copyOf;

public class SBox {

    private final int[] substitution;
    private final int[] reverseSubstitution;


    public SBox(int[] substitution) {
        this.substitution = copyOf(substitution, substitution.length);
        this.reverseSubstitution = reverseSBox(substitution);
    }

    private static int[] reverseSBox(int[] SBox) {
        int[] reverseSBox = new int[SBox.length];
        for (int i = 0; i < SBox.length; i++) {
            reverseSBox[SBox[i]] = i;
        }
        return reverseSBox;
    }

    public int substitute(int input) {
        return substitution[input];
    }

    public int reverseSubstitute(int input) {
        return reverseSubstitution[input];
    }

}
