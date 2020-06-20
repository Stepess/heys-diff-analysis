package ua.stepess.analysis;

import java.util.Comparator;
import java.util.Map;
import java.util.stream.Collectors;

public final class MapUtil {
    private MapUtil() { }

    public static Map<Integer, Integer> head(Map<Integer, Integer> data, int size) {
        return data.entrySet()
                .stream()
                .sorted(Comparator.comparingInt(Map.Entry<Integer, Integer>::getValue).reversed())
                .limit(size)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
