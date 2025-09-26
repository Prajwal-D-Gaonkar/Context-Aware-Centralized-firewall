# Context-Aware Centralized Firewall

## Overview
This project implements a **Context-Aware Centralized Firewall** that monitors network traffic, detects suspicious activity, and provides insights via a centralized manager dashboard. It is designed to simulate traffic, handle attacks, and integrate with machine learning models for anomaly detection.

---

## Features

- **Agent-Based Traffic Monitoring**: Simulates and collects network traffic logs from multiple sources.
- **Centralized Manager API**: Receives logs from agents and processes them for analysis.
- **Attack Simulation**: Includes examples of SQL Injection and XSS attacks for testing detection.
- **Machine Learning Detection**: Analyzes traffic logs to detect anomalies and potential attacks.
- **Dashboard Integration**: Provides a Streamlit dashboard for real-time visualization of network activity.

---

## Folder Structure

Context-Aware-Centralized-firewall/
│
├── agent/ # Traffic-generating agents
│ └── app.py # Main agent script
│
├── attacks/ # Simulated attack scripts
│ ├── sql_injection.py
│ └── xss_attack.py
│
├── dashboard/ # Streamlit dashboard
│ └── streamlit_app.py
│
├── manager/ # Manager API & models
│ ├── api.py
│ └── models.py
│
├── ml/ # Machine learning scripts
│ ├── detector.py
│ └── train_model.py
│
├── docs/ # Documentation
│ └── SETUP.md
│
├── docker-compose.yml
├── requirements.txt
└── README.md