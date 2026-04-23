import pandas as pd
import numpy as np
import joblib
import time
import os
from tensorflow.keras.models import load_model

# ============================================================================
# WHITELIST – IGNORE BENIGN TRAFFIC (STOP FALSE POSITIVES)
# ============================================================================
def is_benign(src_ip, dst_ip, protocol, duration, src_bytes, dst_bytes):
    # Private / local IP ranges
    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                        "127.", "0.0.0.0")
    if src_ip.startswith(private_prefixes) or dst_ip.startswith(private_prefixes):
        return True

    # Multicast and broadcast
    multicast = ("224.0.0.", "239.255.255.", "255.255.255.255")
    if dst_ip.startswith(multicast):
        return True

    # Short UDP discovery packets (mDNS, SSDP, etc.)
    if protocol == 2 and duration < 0.01 and dst_bytes == 0 and src_bytes < 500:
        return True

    # Small ICMP packets (normal ping)
    if protocol == 3 and src_bytes < 100:
        return True

    return False

# ============================================================================
# LOAD MODEL AND SCALER
# ============================================================================
print("=" * 60)
print("LIVE IDS MONITORING (with Whitelist)")
print("=" * 60)

print("\nLoading model and scaler...")
model = load_model('ann_ids_model_41features.h5')
scaler = joblib.load('scaler_41features.save')
print("Model loaded successfully!\n")

# ============================================================================
# CONVERT 5 FEATURES TO 41 FEATURES
# ============================================================================
def convert_5_to_41_features(features_5):
    features_41 = np.zeros(41)
    features_41[0:5] = features_5
    return features_41

# ============================================================================
# READ LATEST CAPTURED FEATURES AND PREDICT (WITH WHITELIST)
# ============================================================================
packet_count = 0
attack_count = 0
normal_count = 0
last_features_count = 0

def predict_from_capture():
    global last_features_count
    try:
        if os.path.exists('live_features.csv'):
            df = pd.read_csv('live_features.csv')
            if len(df) > 0 and len(df) != last_features_count:
                last_features_count = len(df)
                
                # Extract the 5 core features
                if 'duration' in df.columns:
                    features_5 = df.iloc[-1][['duration', 'protocol', 'src_bytes', 'dst_bytes', 'flag']].values
                else:
                    features_5 = df.iloc[-1][0:5].values
                
                # Get metadata
                src_ip = df.iloc[-1].get('src_ip', 'Unknown')
                dst_ip = df.iloc[-1].get('dst_ip', 'Unknown')
                protocol = df.iloc[-1].get('protocol_name', 'Unknown')
                proto_num = features_5[1]
                duration = features_5[0]
                src_bytes = features_5[2]
                dst_bytes = features_5[3]
                
                # ============================================================
                # WHITELIST CHECK – SKIP BENIGN TRAFFIC (NO PRINT)
                # ============================================================
                if is_benign(src_ip, dst_ip, proto_num, duration, src_bytes, dst_bytes):
                    return None
                
                # Prepare 41 features and predict
                features_5 = features_5.reshape(1, -1)
                features_41 = convert_5_to_41_features(features_5[0])
                features_41 = features_41.reshape(1, -1)
                features_scaled = scaler.transform(features_41)
                prediction = model.predict(features_scaled, verbose=0)[0][0]
                
                return {
                    'probability': float(prediction),
                    'classification': 'ATTACK' if prediction > 0.5 else 'NORMAL',
                    'features_5': features_5[0].tolist(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'packet_num': last_features_count
                }
    except Exception as e:
        # Silently ignore errors (e.g., malformed CSV)
        pass
    return None

# ============================================================================
# MAIN LOOP
# ============================================================================
print("Starting live monitoring (whitelist active)...")
print("=" * 60)
print("Benign local/multicast traffic will be ignored.")
print("Press Ctrl+C to stop\n")

try:
    while True:
        result = predict_from_capture()
        if result:
            packet_count += 1
            confidence = result['probability'] * 100 if result['classification'] == 'ATTACK' else (1 - result['probability']) * 100
            
            print("\n" + "=" * 60)
            print(f"PACKET #{result['packet_num']} | Time: {time.strftime('%H:%M:%S')}")
            print("=" * 60)
            print(f"   Source IP:      {result['src_ip']}")
            print(f"   Destination IP: {result['dst_ip']}")
            print(f"   Protocol:       {result['protocol']}")
            print(f"   Features (5):   {result['features_5']}")
            print("-" * 60)
            print(f"   Prediction:     {result['classification']}")
            print(f"   Confidence:     {confidence:.1f}%")
            
            if result['classification'] == 'ATTACK':
                attack_count += 1
                print(f"   VERDICT:       MALICIOUS - Potential attack detected!")
            else:
                normal_count += 1
                print(f"   VERDICT:       BENIGN - Normal traffic")
            
            print(f"   Stats:          Attacks: {attack_count} | Normal: {normal_count} | Total: {packet_count}")
            print("=" * 60)
        
        time.sleep(2)
        
except KeyboardInterrupt:
    print("\n" + "=" * 60)
    print("MONITORING STOPPED")
    print("=" * 60)
    print(f"\nFINAL STATISTICS:")
    print(f"   Total Packets Analyzed: {packet_count}")
    print(f"   Attacks Detected:       {attack_count}")
    print(f"   Normal Traffic:         {normal_count}")
    if packet_count > 0:
        print(f"   Attack Rate: {(attack_count/packet_count)*100:.1f}%")
    print("=" * 60)