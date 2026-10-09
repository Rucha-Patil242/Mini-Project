
package detectors;

import model.LogEvent;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PortScanDetector {

    private static final int HIGH_THRESHOLD = 5;
    private static final long TIME_WINDOW = 60;

    public String detect(List<LogEvent> events) {

        Map<String, Long> firstScanTime = new HashMap<>();
        Map<String, Set<Integer>> scannedPorts = new HashMap<>();

        for (LogEvent event : events) {

            String sourceIp = event.getSrcIp();
            String destinationIp = event.getDstIp();
            int port = event.getPort();

            String key = sourceIp + "->" + destinationIp;

            if (!firstScanTime.containsKey(key)) {

                firstScanTime.put(key, event.getTimestamp());

                Set<Integer> ports = new HashSet<>();
                ports.add(port);

                scannedPorts.put(key, ports);

                continue;
            }

            long firstTime = firstScanTime.get(key);
            long currentTime = event.getTimestamp();

            if (currentTime - firstTime <= TIME_WINDOW) {

                Set<Integer> ports = scannedPorts.get(key);
                ports.add(port);

                int uniquePortCount = ports.size();

                if (uniquePortCount > HIGH_THRESHOLD) {
                    return "HIGH";
                }

            } else {

                firstScanTime.put(key, currentTime);

                Set<Integer> ports = new HashSet<>();
                ports.add(port);

                scannedPorts.put(key, ports);
            }
        }

        return "NORMAL";
    }
}


