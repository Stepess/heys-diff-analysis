package ua.stepess.analysis;

import ua.stepess.util.HeysCipherFactory;

import java.util.Objects;

public class Pair {
    private static final int SAMPLE_COEFFICIENT = 6;

    private final int a;
    private final int b;

    private final double probability;

    public Pair(int a, int b, double probability) {
        this.a = a;
        this.b = b;
        this.probability = probability;
    }

    public Pair(int a, int b) {
        this(a, b, 1.0);
    }

    public int getA() {
        return a;
    }

    public int getB() {
        return b;
    }

    public double getProbability() {
        return probability;
    }

    public int sampleSize() {
        return (int) (SAMPLE_COEFFICIENT / probability);
    }

    public int level() {
        return (int) (probability * (1 << HeysCipherFactory.BLOCK_SIZE));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Pair pair = (Pair) o;
        return a == pair.a &&
                b == pair.b;
    }

    @Override
    public int hashCode() {
        return Objects.hash(a, b);
    }

    @Override
    public String toString() {
        return "Pair{" +
                "a=" + Integer.toHexString(a) +
                ", b=" + Integer.toHexString(b) +
                ", probability=" + probability +
                ", level = " + level() +
                '}';
    }
}
