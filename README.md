# Hybrid Intrusion Detection System (HIDS)

A hybrid IDS that combines signature-based rules with machine learning–based anomaly detection (UNSW-NB15) and surfaces explainable alerts in a SOC-style dashboard.

## Project Overview
- Detects known attacks via signature rules
- Detects unknown/zero-day behaviors via ML
- Generates explainable security alerts
- Visualizes alerts in a streamlined SOC dashboard

## System Architecture
Raw Network Traffic (UNSW-NB15) → Preprocessing → Hybrid Detection Engine (Signature + ML) → alerts.csv → SOC Dashboard (Streamlit)

## Detection Techniques
- **Signature-based:** rule matches for known patterns (e.g., port scanning, ICMP flood, brute-force)
- **Machine learning:** Random Forest on UNSW-NB15 to spot anomalous traffic (unknown, subtle attacks)
- **Hybrid decision logic:**
  - Signature ✅ / ML ❌ → High severity
  - Signature ❌ / ML ✅ → Medium severity
  - Signature ✅ / ML ✅ → High severity
  - Signature ❌ / ML ❌ → Normal traffic

## Dataset
- UNSW-NB15 (modern, realistic traffic; normal + malicious flows)
- Files: `UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv`

## Tech Stack
- Python, pandas, NumPy
- scikit-learn, joblib
- Streamlit (dashboard)

## How to Run
### 1) Preprocess data
```
python -m src.preprocess --input data/raw/UNSW_NB15_training-set.csv --output data/processed/UNSW_NB15_processed.csv
```

### 2) Train the ML model
```
python -m src.train_model
```

### 3) Generate alerts (training data)
```
python -m src.hybrid_detector --raw data/raw/UNSW_NB15_training-set.csv --processed data/processed/UNSW_NB15_processed.csv --clf models/rf_classifier.joblib --output outputs/alerts.csv
```

### 4) Generate alerts (testing data)
```
python -m src.hybrid_detector --raw data/raw/UNSW_NB15_testing-set.csv --processed data/processed/UNSW_NB15_testing_processed.csv --clf models/rf_classifier.joblib --output outputs/alerts_test.csv
```

### 5) Launch the SOC dashboard
```
streamlit run streamlit_app.py
```
- Upload `alerts.csv` or `alerts_test.csv`
- View severity distribution, contextual fields (attack category, protocol, service, duration), detection source, and confidence
- Dashboard is read-only (visualization only; detection runs offline)

## Model Performance (sample)
- Accuracy: ~96%
- Attack recall: ~97%
- Balanced detection vs. false positives

## Sample Attack Categories Detected
- Port scanning
- DoS / DDoS
- Brute force
- Web attacks
- Malware / backdoor
- Unknown / suspicious
- Normal traffic

## Future Enhancements
- Real-time traffic ingestion
- Automated response actions
- Geo-IP visualization
- Threat intelligence integration

## Notes
- Keep `data/`, `models/`, and `outputs/` out of version control (see `.gitignore`).
- Ensure the UNSW-NB15 CSVs are present under `data/raw/` before preprocessing.
