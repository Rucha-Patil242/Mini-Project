package detectors;

import model.Alert;
import model.LogEvent;
import model.Severity;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class BruteForceDetector implements Detector {

    private static final int MEDIUM_THRESHOLD = 4;
    private static final int HIGH_THRESHOLD = 10;
    private static final long TIME_WINDOW = 60000;

    private final Map<String, Integer> failedAttempts = new HashMap<>();
    private final Map<String, Long> firstAttemptTime = new HashMap<>();

    private final Set<String> mediumAlertGenerated = new HashSet<>();
    private final Set<String> highAlertGenerated = new HashSet<>();

    @Override
    public Alert analyze(LogEvent e) {

        if (!"LOGIN_FAILED".equals(e.getType())) {
            return null;
        }

        String sourceIp = e.getSrcIp();
        String destinationIp = e.getDstIp();
        String key = sourceIp + "->" + destinationIp;

        long currentTime = e.getTimestamp();

        if (!firstAttemptTime.containsKey(key)
                || currentTime - firstAttemptTime.get(key) > TIME_WINDOW) {

            firstAttemptTime.put(key, currentTime);
            failedAttempts.put(key, 1);

            mediumAlertGenerated.remove(key);
            highAlertGenerated.remove(key);

            return null;
        }

        int count = failedAttempts.get(key) + 1;
        failedAttempts.put(key, count);

        if (count > HIGH_THRESHOLD && !highAlertGenerated.contains(key)) {

            highAlertGenerated.add(key);

            return new Alert(
                sourceIp,
                "Brute Force Attack",
                Severity.HIGH,
                currentTime
            );
        }

        if (count > MEDIUM_THRESHOLD
                && !mediumAlertGenerated.contains(key)) {

            mediumAlertGenerated.add(key);

            return new Alert(
                sourceIp,
                "Brute Force Attack",
                Severity.MEDIUM,
                currentTime
            );
        }

        return null;
    }
}