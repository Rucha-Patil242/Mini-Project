package ui;

import core.AlertManager;
import core.BlockList;
import core.ReportGenerator;
import core.ResponseEngine;
import detectors.BlacklistDetector;
import model.Alert;
import model.LogEvent;
import parser.LogGenerator;
import parser.LogParser;

import java.io.IOException;
import java.util.List;

public class Main {

    public static void main(String[] args) {
        String logFile = args.length == 0 ? "out/demo-logs.txt" : args[0];

        try {
            if (args.length == 0) {
                LogGenerator.generate(logFile, 1_000);
            }

            List<LogEvent> events = LogParser.parse(logFile);
            BlacklistDetector detector = new BlacklistDetector("data/blacklist.txt");
            AlertManager alertManager = new AlertManager();
            ResponseEngine responseEngine = new ResponseEngine(new BlockList());

            for (LogEvent event : events) {
                Alert alert = detector.analyze(event);
                if (alertManager.raise(alert)) {
                    responseEngine.handleAlert(alert);
                }
            }

            System.out.println(ReportGenerator.buildReport(alertManager.getAllAlerts()));
            System.out.println("Blocked IPs: " + responseEngine.getBlockList().getAll());
        } catch (IOException exception) {
            System.err.println("Could not prepare the demo log: " + exception.getMessage());
            System.exit(1);
        }
    }
}