package ua.stepess.analysis;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class BranchAndLimitSearcher {
    private final Function<Integer, double[]> probabilityFunction;

    public BranchAndLimitSearcher(Function<Integer, double[]> probabilityFunction) {
        this.probabilityFunction = probabilityFunction;
    }

    public Collection<Pair> search(int a, double p, int rounds) {
        Map<Integer, Double> step = Map.of(a, 1.0);
        for (int t = 0; t < rounds; t++) {
            Map<Integer, Double> nextStep = new HashMap<>();
            for (Map.Entry<Integer, Double> item : step.entrySet()) {
                descentStep(nextStep, item.getKey(), item.getValue());
            }
            nextStep.entrySet().removeIf(entry -> entry.getValue() < p);
            step = nextStep;
        }
        return step.entrySet()
                .stream()
                .map(entry -> new Pair(a, entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());
    }

    private void descentStep(Map<Integer, Double> stepItems, int b, double p) {
        double[] distribution = probabilityFunction.apply(b);
        for (int j = 0; j < distribution.length; j++) {
            stepItems.put(j, stepItems.getOrDefault(j, 0.0) + p * distribution[j]);
        }
    }
}
