SUBMISSION PACKAGE
==================

Team:
- Yuval Notkin 206374480
- Shmuel Avivi 318290327
- Ayala Goldman 315261644

Project: Network Traffic Anomaly Monitor (Sniffing-based)

WHAT IS INCLUDED
----------------
1) code/
   - src/*.py          Source code
   - requirements.txt  Dependencies (scapy)
   - README.md         How to install and run

2) docs/
   - FINAL_REPORT.md   Final project documentation (English)
   - WORK_PLAN.md      Work plan (English draft)
   - WORK_PLAN_HE.docx Work plan submitted to lecturer (Hebrew)

3) logs/
   - Experiment results (JSON/CSV/PCAP evidence)

HOW TO RUN (quick)
------------------
cd code
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Live capture (needs sudo):
sudo python src/detector.py --interface en0 --duration 90

# Offline demo:
python src/generate_demo_pcap.py
python src/analyze_pcap.py --pcap ../logs/demo_capture.pcap --output ../logs/pcap_alerts.json

YOU STILL NEED TO ADD (from Moodle)
-----------------------------------
1) Signed originality declaration form (scanned PDF)
2) AI-use declaration form if required by the course
3) Optional: convert FINAL_REPORT.md to PDF/Word
4) Optional: screenshots or short demo video

SUGGESTED ZIP / FOLDER TO UPLOAD
--------------------------------
Upload this whole SUBMISSION folder (or zip it), plus Moodle forms.
