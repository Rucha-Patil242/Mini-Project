package detectors;

import model.Alert;
import model.LogEvent;
import java.util.List;

public interface Detector {
    Alert analyze(List<LogEvent> events);
}
