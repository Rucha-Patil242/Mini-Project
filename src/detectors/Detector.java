

package detectors;

import java.util.List;

import model.Alert;
import model.LogEvent;

public interface Detector {
    Alert analyze( List LogEvent );
}