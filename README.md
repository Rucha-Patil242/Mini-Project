# Mini-Project# 

# CyberShield

A Java-based security monitoring and intrusion detection platform. It ingests network log files, runs multiple detectors over the events, raises and manages alerts, automatically blocks attackers, and produces a report. An analyst controls it through a console menu.

## Features

- Log generation and parsing with safe handling of malformed input
- Three pluggable detectors: brute force, port scan, blacklist
- Alert management with a cooldown, so one attacker does not flood the analyst with duplicates
- Automatic response: HIGH and CRITICAL alerts add the attacker to the blocklist
- Manual block and unblock by the analyst
- Network graph of the traffic seen in the logs
- Summary report of top attackers and alerts by type
- Console menu that ties everything together

## Architecture

```
                    +------------------+
                    |   Console Menu   |   (ui)
                    +--------+---------+
                             |
        +--------------------+--------------------+
        |                                         |
   load / generate logs                     run analysis
        |                                         |
+-------v--------+                       +--------v---------+
| LogGenerator   |                       | DetectionEngine  |   (detectors)
| LogParser      |                       +--------+---------+
+-------+--------+                                |
        |                       +-----------------+-----------------+
  sorted LogEvent list          |                 |                 |
        |              BruteForceDetector  PortScanDetector  BlacklistDetector
        +--------------------->                  |
                                      Alert (or null) per event
                                                 |
                                       +---------v----------+
                                       |    AlertManager    |   (core)
                                       |  cooldown, history |
                                       +----+----------+----+
                                            |          |
                                  +---------v--+   +---v--------------+
                                  |ResponseEngine|  | ReportGenerator |
                                  +------+-----+   +---+--------------+
                                         |             |
                                    +----v----+    report.txt
                                    |BlockList|
                                    +---------+

   NetworkGraph (graph) is built from the same LogEvent list.
   Storage (storage) saves and loads data.
```

## Modules

### Input: `model/` and `parser/`
- **LogEvent**: one parsed log line (timestamp, source IP, port, action and so on). Immutable, with private final fields and getters.
- **LogGenerator**: writes a repeatable test log with normal traffic and injected attacks, so the expected alerts are known in advance.
- **LogParser**: reads the log file into a sorted `ArrayList<LogEvent>`. Blank lines, bad numbers and wrong field counts are skipped rather than crashing the run.

### Detection: `detectors/`
All detectors implement `Detector` (`Alert analyze(LogEvent e)`), so the engine treats them the same and new detectors can be added without changing it.

| Detector | What it catches |
|---|---|
| BruteForceDetector | Repeated failed logins from one IP |
| PortScanDetector | One IP touching many different ports |
| BlacklistDetector | Any traffic from an IP in `data/blacklist.txt` |

**DetectionEngine** loops over the events and passes each one to every detector. Each non-null result is an `Alert` with an IP, a type, a `Severity` and a timestamp.

### Alerts and response: `core/`
- **AlertManager**: receives alerts, applies a cooldown so repeated alerts for the same attacker are reduced to one, and keeps the alert history.
- **ResponseEngine**: when an alert is HIGH or CRITICAL, blocks the attacker's IP.
- **BlockList**: the in-memory set of blocked IPs. Supports block, unblock and lookup. It is lost when the program closes.

### Blacklist vs blocklist

| | Blacklist | Blocklist |
|---|---|---|
| Where | `data/blacklist.txt` (file) | `BlockList` (memory) |
| Filled by | You, by hand, before a run | The program (on HIGH/CRITICAL alerts) or the analyst |
| After the program closes | Still there | Gone |

### Network graph: `graph/`
- **NetworkGraph**: [fill in: what the nodes and edges represent, for example IPs and the connections between them, and what the menu can do with it].

### Storage: `storage/` and `sql/`
- [fill in: what is saved (alerts, blocked IPs, events), where (files or database), and what the scripts in `sql/` create].

### User interface: `ui/`
- **Console menu**: lets the analyst generate or load logs, run the analysis, view alerts, block or unblock IPs, view the blocklist and write the report. [fill in: the exact option list].

### Reporting
- **ReportGenerator**: counts alerts per IP and per type, sorts to find the top 10 attackers, and writes `report.txt`.

## Project structure

```
data/        blacklist.txt, generated logs
docs/        class notes and diagrams
lib/         external libraries (if any)
sql/         database scripts
src/
  model/       LogEvent, Alert, Severity
  parser/      LogGenerator, LogParser
  detectors/   Detector, BruteForceDetector, PortScanDetector, BlacklistDetector, DetectionEngine
  core/        AlertManager, ResponseEngine, BlockList
  graph/       NetworkGraph
  storage/     saving and loading data
  ui/          console menu
test/        test code
```

## Data structures used

| Component | Structure | Why |
|---|---|---|
| LogParser | `ArrayList` + `Comparator` | Append in order, then sort by timestamp, O(n log n) |
| BlacklistDetector | `HashSet` | Is this IP in the list? O(1) on average |
| BlockList | `LinkedHashSet` | No duplicate IPs, O(1) checks, keeps the order IPs were blocked |
| BruteForceDetector | [fill in] | [fill in] |
| PortScanDetector | [fill in] | [fill in] |
| AlertManager | [fill in] | [fill in] |
| NetworkGraph | [fill in] | [fill in] |
| ReportGenerator | `HashMap` + sort | Count alerts per IP and per type, then sort for the top 10 |

## Build

Requires JDK 11 or newer. From the project root in PowerShell:

```powershell
$sources = Get-ChildItem src -Recurse -Filter *.java | ForEach-Object { $_.FullName }
javac --release 11 -d out $sources
```

The project currently has no application entry point, so the compiled classes cannot be launched as a standalone program yet.

## Testing

Test data is generated with a fixed seed, so every run is identical. The attacks are injected on purpose, so the expected results are known:

| Check | Expected |
|---|---|
| Parsed events | 1022, skipped 0 |
| Brute force | 1 alert from 203.0.113.9 (on the 5th failure) |
| Port scan | 1 alert from 198.51.100.7 (on the 10th port) |
| Blacklist | 4 raw alerts from 45.33.32.156, reduced to 1 by the AlertManager cooldown |

Edge cases covered: empty file, missing file, malformed lines, bad port numbers. A timing test runs the full pipeline on 50,000 lines.

## Team

| Member | Responsibility |
|---|---|
| A | Input and reporting: LogEvent, LogGenerator, LogParser, BlacklistDetector,BlockList, ReportGenerator, testing |
| B | Detectors: BruteForceDetector, PortScanDetector, DetectionEngine |
| C | Response: AlertManager, ResponseEngine  |
| D | Console menu and user interface |

Replace A, B, C and D with names, and add the owners of NetworkGraph and storage.

## Limitations and future work

- The blocklist is in memory only. It could be saved to a file and loaded at startup.
- The blacklist is edited by hand. A menu option could add IPs to it.