# ANN-Based Intrusion Detection System (IDS)

## Overview

This project implements a real-time Intrusion Detection System (IDS) using:

* Packet capture with Scapy
* Artificial Neural Network (ANN) for attack classification
* ICMP Flood (DoS) detection logic
* API-based communication with a live dashboard

The system monitors network traffic, detects malicious activity, and displays results in real time.

---

## Key Features

| Feature                   | Description                                                                     |
| ------------------------- | ------------------------------------------------------------------------------- |
| High accuracy             | Achieves 100% accuracy on a balanced test set (100 attack + 100 normal samples) |
| 41-feature model          | Uses the full NSL-KDD feature set (padded to 41 features)                       |
| REST API                  | `/predict` endpoint returns attack probability                                  |
| Interactive dashboard     | Manual input, confidence visualization, and statistics                          |
| Live ICMP flood detection | Rule-based detection for ping flood attacks                                     |
| Zero-day capable          | Identifies anomalous patterns beyond known signatures                           |

---

## Testing and Validation

### Automated Accuracy Test

Run the test script:

```bash
python test_automated.py
```

### Expected Output

```text
Attack Test Results: 100/100 correct (100.0%)
Normal Test Results: 100/100 correct (100.0%)
TOTAL ACCURACY: 100.00% (200/200)
```

---

## Notes on Evaluation

* The model is evaluated on a balanced test dataset
* Accuracy reflects performance on known labeled samples
* Zero-day capability refers to detecting anomalous behavior patterns

---

## Machine Learning Model

* Model: Artificial Neural Network (ANN)
* Dataset: NSL-KDD
* Features: 41 network traffic features
* Output: Attack classification (e.g., Neptune, Normal)

---

## System Architecture

```
capture.py  →  api.py  →  dashboard.html
   │
   └────→ live_predict.py (ML Classification)
```

---

## Project Structure

```
ANN-IDS-System/
│── capture.py                 # Packet capture and ICMP detection
│── api.py                     # Backend API (Flask)
│── live_predict.py            # ANN-based prediction
│── train_41features.py        # Model training script
│── dashboard.html             # Frontend interface
│── requirements.txt
│── README.md
│
│── model/
│    ├── ann_ids_model_41features.h5
│    ├── scaler.save
│    └── scaler_41features.save
│
│── screenshots/
│    └── demo.png
```

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/your-username/ANN-IDS-System.git
cd ANN-IDS-System
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the System

### Step 1: Start API

```bash
python api.py
```

### Step 2: Start Packet Capture

```bash
python capture.py
```

### Step 3: Run Prediction

```bash
python live_predict.py
```

### Step 4: Open Dashboard

Open `dashboard.html` in a web browser

---

## How It Works

1. `capture.py` captures live network packets
2. Detects ICMP flood activity
3. Sends data to `api.py`
4. API updates system status
5. `dashboard.html` fetches and displays results
6. `live_predict.py` performs machine learning classification

---

## Sample Output

```
ICMP FLOOD ATTACK DETECTED
Source IP: 142.250.195.78
Destination IP: 10.2.100.254
Packet rate: 4 packets/sec
```

---

## Dataset

This project uses the NSL-KDD dataset.

Download from:

* https://www.kaggle.com/datasets/hassan06/nslkdd
* https://github.com/jmnwong/NSL-KDD-Dataset

Place the dataset files in:

```
data/
│── KDDTrain+.txt
│── KDDTest+.txt
```

---

## Demo
Terminal 1 (Administrator)
python capture_icmp.py
Terminal 2 
ping google.com -l 1000 -n 200
Expected alert in Terminal 1:

   ICMP FLOOD ATTACK detected at HH:MM:SS
   Source IP:      your.public.ip
   Destination IP: 142.250.185.46
   Packet rate:    45 packets/sec
   Packet size:    1042 bytes

---

## Keywords

IDS, Cybersecurity, Machine Learning, Intrusion Detection, ANN, Network Security, DoS Detection, NSL-KDD

---

## Future Improvements

* Extend detection to TCP/UDP-based attacks
* Upgrade to deep learning models (e.g., LSTM)
* Cloud deployment
* Enhanced dashboard with analytics

---

## Author

Aishwarya Kale
Cybersecurity Student

---

## License

This project is intended for educational and research purposes.
