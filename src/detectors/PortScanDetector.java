
package detectors;

import model.Alert;
import model.LogEvent;
import model.Severity;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class PortScanDetector implements Detector {

    private static final int HIGH_THRESHOLD = 5;
    private static final long TIME_WINDOW = 60;

    private final Map<String, Long> firstScanTime = new HashMap<>();
    private final Map<String, Set<Integer>> scannedPorts = new HashMap<>();

    @Override
    public Alert analyze(LogEvent e) {
        String sourceIp = e.getSrcIp();
        String destinationIp = e.getDstIp();
        String key = sourceIp + "->" + destinationIp;

        long currentTime = e.getTimestamp();

        if (!firstScanTime.containsKey(key)
                || currentTime - firstScanTime.get(key) > TIME_WINDOW) {

            firstScanTime.put(key, currentTime);

            Set<Integer> ports = new HashSet<>();
            ports.add(e.getPort());
            scannedPorts.put(key, ports);

            return null;
        }

        Set<Integer> ports = scannedPorts.get(key);
        ports.add(e.getPort());

        if (ports.size() > HIGH_THRESHOLD) {
            return new Alert(
                sourceIp,
                "Port Scan",
                Severity.HIGH,
                currentTime
            );
        }

        return null;
    }
}
