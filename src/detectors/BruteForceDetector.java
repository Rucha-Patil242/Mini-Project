
package detectors;

import model.Alert;
import model.LogEvent;
import model.Severity;

import java.util.HashMap;
import java.util.Map;

public class BruteForceDetector implements Detector {

    private static final int CRITICAL_THRESHOLD = 10;
    private static final long TIME_WINDOW = 60;

    private final Map<String, Integer> failedAttempts = new HashMap<>();
    private final Map<String, Long> firstAttemptTime = new HashMap<>();

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

            return null;
        }

        int count = failedAttempts.get(key);
        count++;

        failedAttempts.put(key, count);

        if (count > CRITICAL_THRESHOLD) {
            return new Alert(
                sourceIp,
                "Brute Force Attack",
                Severity.CRITICAL,
                currentTime
            );
        }

        return null;
    }
}
