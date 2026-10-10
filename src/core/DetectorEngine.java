
package core;

import detectors.Detector;
import detectors.PortScanDetector;
import detectors.BruteForceDetector;
import model.Alert;
import model.LogEvent;

import java.util.ArrayList;
import java.util.List;

public class DetectorEngine {

    private final List<Detector> detectors = new ArrayList<>();

    public DetectorEngine() {
        detectors.add(new PortScanDetector());
        detectors.add(new BruteForceDetector());
    }

    public List<Alert> analyze(LogEvent event) {
        List<Alert> alerts = new ArrayList<>();

        for (Detector detector : detectors) {
            Alert alert = detector.analyze(event);

            if (alert != null) {
                alerts.add(alert);
            }
        }

        return alerts;
    }
}

