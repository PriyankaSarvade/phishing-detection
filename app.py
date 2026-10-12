from pyexpat import features

from flask import Flask, render_template, request
import joblib
import pandas as pd

# Import your extraction function from the src folder
from src.feature_extraction import extract_url_features

app = Flask(__name__)

# Load the trained model when the app starts
# (Make sure this path matches exactly where your .pkl file is saved!)
model = joblib.load('src/phishing_model.pkl')

@app.route('/')
def home():
    # Load the main HTML page
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        target_url = request.form['url']
        
        # 1. Extract features and convert to DataFrame
        features = extract_url_features(target_url)
        features_df = pd.DataFrame([features])
        
        # 2. Get prediction and confidence probabilities
        prediction_value = model.predict(features_df)[0]
        probabilities = model.predict_proba(features_df)[0]
        
        # Calculate confidence percentage (highest probability)
        confidence = round(max(probabilities) * 100, 2)
        
        # 3. Format message
        if prediction_value == 1:
            result = "⚠️ Warning: This is a Phishing/Malicious Link!"
        else:
            result = "✅ Safe: This looks like a Legitimate Link."
            
        # 4. Pass confidence score to the template
        return render_template(
            'index.html',
            original_url=target_url,
            prediction_text=result,
            confidence=confidence
        )
if __name__ == '__main__':
    # Run the app locally in debug mode
    app.run(debug=True)