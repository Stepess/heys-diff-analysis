package ua.stepess.crypto.diff;

public class Differential {
    int a;
    int b;
    double probability;

    public Differential(int a, int b, double probability) {
        this.a = a;
        this.b = b;
        this.probability = probability;
    }

    public static Differential of(int a, int b, double probability) {
        return new Differential(a, b, probability);
    }

    @Override
    public String toString() {
        return "Differential{" +
                "a=" + a +
                ", b=" + b +
                ", probability=" + probability +
                '}';
    }

    public int getA() {
        return a;
    }

    public void setA(int a) {
        this.a = a;
    }

    public int getB() {
        return b;
    }

    public void setB(int b) {
        this.b = b;
    }

    public double getProbability() {
        return probability;
    }

    public void setProbability(double probability) {
        this.probability = probability;
    }
}
