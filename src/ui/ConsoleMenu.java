package ui;

import core.AlertManager;
import core.BlockList;
import core.DetectorEngine;
import core.ReportGenerator;
import core.ResponseEngine;
import detectors.BlacklistDetector;
import graph.NetworkGraph;
import model.Alert;
import model.LogEvent;
import parser.LogGenerator;
import parser.LogParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class ConsoleMenu {
    Scanner sc = new Scanner(System.in);
    NetworkGraph graph = new NetworkGraph();
    ArrayList<LogEvent> events = new ArrayList<>();
    boolean logsLoaded = false;

    AlertManager alertManager = new AlertManager();
    BlockList blockList = new BlockList();
    ResponseEngine responseEngine = new ResponseEngine(blockList);

    public void start() {
        int choice = -1;

        do {
            System.out.println();
            System.out.println("1  Generate logs");
            System.out.println("2  Load logs from file");
            System.out.println("3  Run detection");
            System.out.println("4  Show next alert");
            System.out.println("5  Show alert history");
            System.out.println("6  Show blocklist");
            System.out.println("7  Block IP manually");
            System.out.println("8  Undo last block");
            System.out.println("9  Reachable hosts (BFS)");
            System.out.println("10 Attack path (DFS)");
            System.out.println("11 Generate report");
            System.out.println("0  Exit");
            System.out.print("Choice: ");

            try {
                choice = Integer.parseInt(sc.nextLine().trim());
            } catch (NumberFormatException e) {
                System.out.println("Please enter a number.");
                choice = -1;
                continue;
            }

            if (choice == 1) {
                try {
                    LogGenerator.generate("data/logs.txt", 1000);
                    loadLogs();
                } catch (IOException e) {
                    System.out.println("Could not write logs.");
                }

            } else if (choice == 2) {
                loadLogs();

            } else if (choice == 3) {
                if (!logsLoaded) {
                    System.out.println("Load logs first.");
                } else {
                    runDetection();
                }

            } else if (choice == 4) {
                Alert next = alertManager.nextAlert();
                if (next == null) {
                    System.out.println("No pending alerts.");
                } else {
                    printAlert(next);
                }

            } else if (choice == 5) {
                List<Alert> history = alertManager.getHistory();
                if (history.isEmpty()) {
                    System.out.println("No alerts yet.");
                } else {
                    for (Alert a : history) {
                        printAlert(a);
                    }
                }

            } else if (choice == 6) {
                List<String> blocked = blockList.getAll();
                if (blocked.isEmpty()) {
                    System.out.println("Blocklist is empty.");
                } else {
                    System.out.println("Blocked IPs: " + blocked);
                }

            } else if (choice == 7) {
                System.out.print("IP to block: ");
                String ip = sc.nextLine().trim();
                if (responseEngine.block(ip)) {
                    System.out.println(ip + " is now blocked.");
                } else {
                    System.out.println("Not blocked (already blocked or empty).");
                }

            } else if (choice == 8) {
                String undone = responseEngine.undo();
                if (undone == null) {
                    System.out.println("Nothing to undo.");
                } else {
                    System.out.println("Unblocked " + undone);
                }

            } else if (choice == 9) {
                System.out.print("Compromised IP: ");
                String ip = sc.nextLine().trim();
                List<String> reachable = graph.bfs(ip);
                if (reachable.isEmpty()) {
                    System.out.println("Unknown host.");
                } else {
                    System.out.println("Reachable hosts: " + reachable);
                }

            } else if (choice == 10) {
                System.out.print("Attacker IP: ");
                String start = sc.nextLine().trim();
                System.out.print("Critical server IP: ");
                String target = sc.nextLine().trim();
                List<String> path = graph.dfsPath(start, target);
                if (path == null || path.isEmpty()) {
                    System.out.println("No path found.");
                } else {
                    System.out.println("Path: " + String.join(" -> ", path));
                }

            } else if (choice == 11) {
                if (alertManager.getAllAlerts().isEmpty()) {
                    System.out.println("No alerts yet. Run detection first (option 3).");
                } else {
                    try {
                        ReportGenerator.generate(alertManager, "data/report.txt");
                        System.out.println("Report written to data/report.txt");
                        System.out.println(ReportGenerator.buildReport(alertManager.getAllAlerts()));
                    } catch (IOException e) {
                        System.out.println("Could not write report: " + e.getMessage());
                    }
                }

            } else if (choice != 0) {
                System.out.println("Invalid option.");
            }

        } while (choice != 0);

        System.out.println("Goodbye.");
    }

    // reads data/logs.txt into events, then builds the network graph
    void loadLogs() {
        events = LogParser.parse("data/logs.txt");
        logsLoaded = !events.isEmpty();
        System.out.println("Loaded " + events.size() + " events.");
        if (logsLoaded) {
            buildGraph();
        }
    }

    // one edge per connection (the graph ignores repeated pairs)
    void buildGraph() {
        graph = new NetworkGraph();
        for (LogEvent e : events) {
            graph.addEdge(e.getSrcIp(), e.getDstIp());
        }
        System.out.println("Network graph built.");
    }

    // option 3: run every event through the detectors
    void runDetection() {
        // start fresh each run
        alertManager = new AlertManager();
        blockList = new BlockList();
        responseEngine = new ResponseEngine(blockList);

        DetectorEngine engine = new DetectorEngine();                      // port scan + brute force
        BlacklistDetector blacklist = new BlacklistDetector("data/blacklist.txt");

        int accepted = 0;
        for (LogEvent e : events) {
            List<Alert> alerts = engine.analyze(e);

            Alert blacklisted = blacklist.analyze(e);
            if (blacklisted != null) {
                alerts.add(blacklisted);
            }

            for (Alert a : alerts) {
                if (alertManager.raise(a)) {
                    accepted++;
                    responseEngine.handleAlert(a);
                }
            }
        }
        System.out.println("Detection finished. " + accepted + " alerts, "
                + blockList.size() + " IPs blocked.");
    }

        void printAlert(Alert a) {
        System.out.println(a);
    }
}