import os
import sys
import joblib
import pandas as pd

# Ensure local imports work regardless of execution directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from feature_extraction import extract_url_features

# Load trained model safely using absolute paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'src', 'phishing_model.pkl')

try:
    model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Run 'train_model.py' first.")

def predict_url(url, return_confidence=False):
    """
    Predicts whether a given URL is a phishing attempt or safe.
    """
    # Clean input URL
    url = url.strip()
    if not url:
        return "Invalid input URL."

    # Extract features and convert to DataFrame matching model inputs
    features = extract_url_features(url)
    features_df = pd.DataFrame([features])
    
    # Predict class and probabilities
    prediction = model.predict(features_df)[0]
    
    if return_confidence and hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features_df)[0]
        confidence = max(probabilities) * 100
        status = "Phishing Website Detected!" if prediction == 1 else "Safe Website"
        return f"{status} (Confidence: {confidence:.1f}%)"
    
    return "Phishing Website Detected!" if prediction == 1 else "Safe Website"

if __name__ == "__main__":
    print("--- Phishing Detector Terminal Test ---")
    while True:
        test_url = input("\nEnter URL to check (or type 'exit' to quit): ").strip()
        if test_url.lower() in ['exit', 'quit', 'q']:
            print("Exiting scanner...")
            break
        if test_url:
            result = predict_url(test_url, return_confidence=True)
            print(f"Result: {result}")