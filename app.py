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
        # 1. Grab the URL typed into the HTML form
        target_url = request.form['url']
        
        # 2. Extract the features (Count dots, length, HTTPS, etc.)
        features = extract_url_features(target_url)
        
        # 3. Convert to a Pandas DataFrame (Models require 2D data structures)
        # We wrap 'features' in a list [] so it forms a single row
        features_df = pd.DataFrame([features])
        
        # 4. Ask the model to predict (Output is usually [0] or [1])
        prediction_array = model.predict(features_df)
        prediction_value = prediction_array[0]

        print(features) # <-- Just add this one single line here!
        
        # 5. Translate the number back into English
        if prediction_value == 1:
            result = "⚠️ Warning: This is a Phishing/Malicious Link!"
        else:
            result = "✅ Safe: This looks like a Legitimate Link."
            
        # 6. Send the result back to the HTML page to display it
        return render_template('index.html', original_url=target_url, prediction_text=result)

if __name__ == '__main__':
    # Run the app locally in debug mode
    app.run(debug=True)