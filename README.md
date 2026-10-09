# Mini-Project# 

## CyberShield

A Java-based security monitoring and intrusion detection tool. It reads network log files, runs several detectors over the events, raises alerts, blocks attackers, and writes a summary report.

## What it does

1. **Generates or loads logs.** `LogGenerator` creates a test log file with normal traffic and injected attacks. `LogParser` reads it into `LogEvent` objects and sorts them by time.
2. **Detects attacks.** Each detector looks at one event at a time and returns an `Alert` or `null`.
3. **Responds.** Alerts are collected, and attackers with a HIGH or CRITICAL alert are added to the blocklist.
4. **Reports.** A report lists the top attackers and the alerts by type.

## Detectors

| Detector | What it catches |
|---|---|
| `BruteForceDetector` | Repeated failed logins from one IP |
| `PortScanDetector` | One IP touching many different ports |
| `BlacklistDetector` | Any traffic from an IP listed in `data/blacklist.txt` |

All detectors implement the `Detector` interface (`Alert analyze(LogEvent e)`), so the detection engine can run them all the same way and new detectors can be added without changing the engine.

## Blacklist vs blocklist

| | Blacklist | Blocklist |
|---|---|---|
| Where | `data/blacklist.txt` (file) | `BlockList` class (memory) |
| Filled by | You, by hand, before a run | The program (on HIGH/CRITICAL alerts) or the analyst |
| After the program closes | Still there | Gone |

## Project structure

```
data/        blacklist.txt, generated logs
docs/        class notes and diagrams
lib/         external libraries (if any)
sql/         database scripts
src/
  model/       LogEvent, Alert, Severity
  parser/      LogGenerator, LogParser
  detectors/   Detector, BruteForceDetector, PortScanDetector, BlacklistDetector
  core/        BlockList and the alert/response classes
  graph/       NetworkGraph
  storage/     saving data
  ui/          console menu
test/        test code
```

## Data structures used

| Class | Structure | Why |
|---|---|---|
| `LogParser` | `ArrayList` + `Comparator` | Events are appended in order and sorted by timestamp, O(n log n) |
| `BlacklistDetector` | `HashSet` | One question per event: is this IP in the list? O(1) on average |
| `BlockList` | `LinkedHashSet` | No duplicate IPs, O(1) checks, remembers the order IPs were blocked |

## How the pieces connect

```
LogGenerator --writes--> data/logs.txt --read by--> LogParser
                                                       |
                                              sorted LogEvent list
                                                       |
                                                DetectionEngine
                                    +------------------+------------------+
                                    |                  |                  |
                            BruteForceDetector  PortScanDetector  BlacklistDetector
                                    +------------------+------------------+
                                                       |
                                                    Alert / null
                                                       |
                                          alert manager and response
                                                       |
                                                   BlockList
                                                       |
                                                 report.txt
```

## Log format

Each line is one event, with comma-separated fields. `LogGenerator` writes this format and `LogParser` reads it, using the same `LogEvent.toString()`. Lines that are blank, have the wrong number of fields, or have an invalid number or port are skipped instead of crashing the run.

## Build and run

Requires JDK 11 or newer. From the project root:

```
javac -d out src/model/*.java src/parser/*.java src/detectors/*.java src/core/*.java src/graph/*.java
java -cp out <MainClass>
```

Replace `<MainClass>` with the class that contains `main` (for example `ui.ConsoleMenu`), and add any other source folders you use to the `javac` line.

## Testing

Test data is generated with a fixed seed (`new Random(42)`), so every run produces the same logs. The attacks are injected on purpose, so the expected results are known:

| Check | Expected |
|---|---|
| Parsed events | 1022, skipped 0 |
| Brute force | 1 alert from 203.0.113.9 (on the 5th failure) |
| Port scan | 1 alert from 198.51.100.7 (on the 10th port) |
| Blacklist | 4 raw alerts from 45.33.32.156, reduced to 1 after the alert manager's cooldown |

Edge cases covered: empty file, missing file, malformed lines, bad port numbers. A timing test runs the parser and detectors on 50,000 lines.

## Team

| Member | Responsibility |
|---|---|
| Rucha Patil | Input and reporting: LogEvent, LogGenerator, LogParser, BlacklistDetector, ReportGenerator, testing , BlockList |
| Radha Aole | Detectors and detection engine |
| Sneha Patil | Alerts, response and BlockList |
| Ruchika Apte | Console menu and user interface |


## Limitations and future work

- The blocklist is kept in memory only, so it is lost when the program closes. It could be saved to a file and loaded at startup.
- The blacklist is edited by hand. A menu option could add IPs to it.