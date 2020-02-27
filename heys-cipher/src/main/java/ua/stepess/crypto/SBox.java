package ua.stepess.crypto;

import static java.util.Arrays.copyOf;

public class SBox {

    private int[] substitution;

    public SBox(int[] substitution) {
        this.substitution = copyOf(substitution, substitution.length);
    }

    public int substitute(int input) {
        return substitution[input];
    }

    public int reverseSubstitute(int input) {
        for (int i = 0; i < substitution.length; i++) {
            if (substitution[i] == input) {
                return i;
            }
        }
        throw new ArithmeticException("Element not found");
    }

}
