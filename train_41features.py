import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
import joblib

print("Loading dataset...")
data = pd.read_csv("KDDTrain+.txt", header=None)
print(f"Shape: {data.shape}")

# Encode categorical columns (1=protocol, 2=service, 3=flag)
for col in [1,2,3]:
    data[col] = LabelEncoder().fit_transform(data[col])

# Features: all rows, columns 0 to 40 (first 41 columns)
X = data.iloc[:, 0:41].values.astype(float)
# Labels: column 41
y_raw = data.iloc[:, 41].values
y = np.array([0 if label == "normal" else 1 for label in y_raw])
print(f"Normal: {(y==0).sum()}, Attack: {(y==1).sum()}")

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Build model
model = Sequential([
    Dense(64, activation='relu', input_shape=(41,)),
    Dense(32, activation='relu'),
    Dense(16, activation='relu'),
    Dense(1, activation='sigmoid')
])
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.2, verbose=1)

# Evaluate
loss, acc = model.evaluate(X_test, y_test, verbose=0)
print(f"\nTest Accuracy: {acc:.4f}")

# Save
model.save('ann_ids_model_41features.h5')
joblib.dump(scaler, 'scaler_41features.save')
print("Model and scaler saved successfully!")