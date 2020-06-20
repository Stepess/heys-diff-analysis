package ua.stepess;

import ua.stepess.analysis.BranchAndLimitSearcher;
import ua.stepess.analysis.DataUtil;
import ua.stepess.analysis.DifferentialCryptoanalysis;
import ua.stepess.analysis.Pair;
import ua.stepess.util.FileUtil;
import ua.stepess.util.HeysCipherFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class AppRunner {

    /*public static void main(String[] args) {
        var sBox = SBoxFactory.getDefaultSBox();
    }*/

    public static void main(String[] args) {
        //generateApproximations();

        Collection<Pair> pairs = FileUtil.readPairs(Path.of("data/diff/differentials.json"));
        recoverLast(pairs);
    }

    private static void recoverLast(Collection<Pair> differentials) {
        //int[] keys = DataUtil.genKeys();
        int[] keys = {29345, 289, 57561, 51768, 46247, 8401, 35777};

        System.out.println("Should be: " + Integer.toHexString(keys[keys.length - 1]));

        List<Pair> filteredDifferentials = differentials.stream()
                .filter(p -> DifferentialCryptoanalysis.differentialSize(p.getB()) == 4)
                .filter(p -> p.level() > 35)
                .peek(System.out::println)
                .collect(Collectors.toList());

        for (Pair differential : filteredDifferentials) {
            Map<Integer, Integer> data = DataUtil.generateData(keys, differential.sampleSize(), differential.getA());

            int key = DifferentialCryptoanalysis.recoverLast(data, differential.getA(), differential.getB());
            System.out.println(Integer.toHexString(key));
        }

    }

    private static void generateApproximations() {
        double p = 1.0 / (1 << 12);
        BranchAndLimitSearcher searcher = new BranchAndLimitSearcher(DifferentialCryptoanalysis::differenceProbabilityDistribution);
        Collection<Pair> pairs = new ArrayList<>();
        for (int i = 0; i < HeysCipherFactory.N; i++) {
            for (int j = 1; j < (1 << HeysCipherFactory.N); j++) {
                int a = j << (4 * i);
                System.out.println("a = " + Integer.toHexString(a));
                pairs.addAll(searcher.search(a, p, 5));
            }
        }
        System.out.println("Approximations:");
        pairs.forEach(System.out::println);
        System.out.println("Total size = " + pairs.size());

        FileUtil.write(Path.of("./data/diff/differentials.json"), pairs);
    }

}
