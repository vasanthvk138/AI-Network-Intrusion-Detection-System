# AI-Powered Network Intrusion Detection & Threat Alert System

## 📌 Overview

The AI-Powered Network Intrusion Detection & Threat Alert System is a machine-learning-based cybersecurity project designed to detect and classify malicious network traffic in real time.

The system analyzes network traffic and uses a trained machine learning model to identify potential attacks such as DDoS, Port Scanning, Brute Force, Web Attacks, and other malicious activities. Detected threats are displayed through a web-based monitoring dashboard.

## 🚀 Features

- Real-time network traffic monitoring
- Machine learning-based intrusion detection
- Network attack classification
- Threat detection and alert generation
- Web-based monitoring dashboard
- Dataset preprocessing and model training
- Network packet capture using Scapy
- SQLite database for storing security logs
- Attack simulation for testing
- Visual monitoring of detected threats

## 🛠️ Technologies Used

### Programming
- Python
- HTML
- CSS
- JavaScript

### Cybersecurity Tools & Libraries
- Scapy
- Wireshark
- Nmap
- Network packet analysis

### Machine Learning
- Scikit-learn
- Pandas
- NumPy
- Random Forest
- StandardScaler
- Label Encoder

### Backend & Database
- Flask
- SQLite

## 📂 Project Structure

```text
AI-Network-Intrusion-Detection-System/
│
├── data/
│   ├── cicids_sample.csv
│   ├── final_dataset.csv
│   └── CICIDS datasets
│
├── database/
│   └── logs.db
│
├── model/
│   ├── features.pkl
│   ├── label_encoder.pkl
│   ├── model.pkl
│   └── scaler.pkl
│
├── src/
│   ├── alert.py
│   ├── capture.py
│   ├── database.py
│   ├── detector.py
│   ├── train.py
│   └── attack simulation scripts
│
├── templates/
│   ├── dashboard.html
│   ├── index.html
│   └── monitoring.html
│
├── app.py
├── alert.py
├── attack_simulator.py
├── check_dataset.py
├── init_db.py
├── requirements.txt
└── README.md