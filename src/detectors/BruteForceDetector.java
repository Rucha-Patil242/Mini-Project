
package detectors;

import model.LogEvent;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BruteForceDetector {

    private static final int CRITICAL_THRESHOLD = 10;
    private static final long TIME_WINDOW = 60;

    public String detect(List<LogEvent> events) {

        Map<String, Integer> failedAttempts = new HashMap<>();
        Map<String, Long> firstAttemptTime = new HashMap<>();

        for (LogEvent event : events) {

            if (!"LOGIN_FAILED".equals(event.getType())) {
                continue;
            }

            String sourceIp = event.getSrcIp();
            String destinationIp = event.getDstIp();

            String key = sourceIp + "->" + destinationIp;

            if (!firstAttemptTime.containsKey(key)) {

                firstAttemptTime.put(key, event.getTimestamp());
                failedAttempts.put(key, 1);

                continue;
            }

            long firstTime = firstAttemptTime.get(key);
            long currentTime = event.getTimestamp();

            if (currentTime - firstTime <= TIME_WINDOW) {

                int count = failedAttempts.get(key);

                count++;

                failedAttempts.put(key, count);

                if (count > CRITICAL_THRESHOLD) {
                    return "CRITICAL";
                }

            } else {

                firstAttemptTime.put(key, currentTime);
                failedAttempts.put(key, 1);
            }
        }

        return "NORMAL";
    }
}


