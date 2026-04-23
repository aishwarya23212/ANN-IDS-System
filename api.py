from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import joblib
from tensorflow.keras.models import load_model

app = Flask(__name__)
CORS(app)

model = load_model('ann_ids_model_41features.h5')
scaler = joblib.load('scaler_41features.save')
print("Model loaded")

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    f5 = np.array(data['features']).reshape(1, -1)
    f41 = np.zeros((1, 41))
    f41[0, :5] = f5[0, :5]
    f41_scaled = scaler.transform(f41)
    prob = model.predict(f41_scaled, verbose=0)[0][0]
    cls = 'Attack' if prob > 0.5 else 'Normal'
    conf = prob * 100 if cls == 'Attack' else (1 - prob) * 100
    return jsonify({'probability': float(prob), 'classification': cls, 'confidence': float(conf)})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/stats', methods=['GET'])
def stats():
    return jsonify({'total_predictions': 0, 'attacks_detected': 0, 'normal_traffic': 0, 'attack_rate': 0})

@app.route('/alerts', methods=['GET'])
def alerts():
    return jsonify({'alerts': []})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
