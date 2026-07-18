# Mini Project Work Plan

## Project Title
Vulnerability Monitoring and Mapping Based on Network Traffic Sniffing  
(Basic Network Traffic Anomaly Monitor)

## Scope and System Boundaries
The project implements a defensive tool that monitors local network traffic and detects suspicious behavior patterns in a controlled lab environment.

Included in scope:
- Capturing packets from a selected network interface.
- Detecting three basic anomaly patterns:
  - High-rate connections to many destination ports (scan-like behavior).
  - ARP mapping conflicts (possible ARP spoofing / MITM indication).
  - DNS burst behavior from the same source.
- Writing alerts to terminal and JSON log files.

Out of scope:
- Exploit development.
- Malware deployment.
- Attacking real production systems.

## Main Goal and Objectives
Goal:
Build a practical, lightweight security monitoring tool that demonstrates attacker-style traffic patterns and defensive detection logic.

Objectives:
1. Implement live packet sniffing.
2. Implement simple rule-based anomaly detection.
3. Produce structured incident logs.
4. Demonstrate detection in controlled scenarios.
5. Document strengths, weaknesses, and future improvements.

## Scenarios
1. Normal baseline traffic (web browsing / DNS lookups) to validate low-noise behavior.
2. Port-scan simulation in local lab to trigger scan detection.
3. ARP conflict simulation in local lab to trigger ARP alert.
4. DNS flood-like burst simulation to trigger DNS anomaly alert.

## Milestones and Timeline
Week 1:
- Finalize requirements and architecture.
- Set up Python environment and packet capture.
- Implement baseline logging.

Week 2:
- Implement scan detector.
- Implement ARP conflict detector.
- Implement DNS burst detector.

Week 3:
- Run controlled tests for each scenario.
- Tune thresholds and reduce false positives.
- Add log export and summary output.

Week 4:
- Complete final documentation.
- Prepare demo steps and screenshots.
- Final review and submission package.

## Challenges and Risks
- Generating realistic yet safe test traffic.
- Avoiding excessive false positives on noisy networks.
- Platform permissions for packet capture.
- Selecting thresholds that work across different environments.

## Project Strengths
- Clear fit to network security course goals.
- Easy to explain and demonstrate with measurable outputs.
- Defensive and safe implementation in a lab setup.
- Extendable to additional IDS features in future work.

## Tools and Technologies
- Python 3.10+
- scapy
- Standard library modules: argparse, collections, datetime, json, pathlib

## Deliverables
1. Source code of the anomaly monitor.
2. Usage instructions.
3. Final report with:
   - What the tool does and goal coverage.
   - Encountered issues.
   - Strengths and limitations.
   - Technical explanation of central components.
   - References to tools/libraries used.
