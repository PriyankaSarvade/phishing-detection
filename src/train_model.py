import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from preprocessing import load_and_preprocess_data
from feature_extraction import extract_url_features

# 1. Load preprocessed data
dataset_path = "dataset/phishing_dataset.csv"
df = load_and_preprocess_data(dataset_path)

print("Columns in dataset:", df.columns.tolist())

# Find the URL column name dynamically
url_col = next((col for col in df.columns if col.lower() in ['url', 'domain', 'link', 'urls']), df.columns[0])
print(f"Using column '{url_col}' for feature extraction...")

# 2. Extract features for all URLs
print("Extracting features from dataset...")
feature_list = df[url_col].apply(extract_url_features).tolist()
X = pd.DataFrame(feature_list)

# Find target label column
label_col = 'label' if 'label' in df.columns else 'type'
y = df[label_col]

# 3. Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 4. Train Random Forest Model
print("Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# 5. Evaluate Accuracy & Classification Metrics
predictions = model.predict(X_test)
print(f"\nModel Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%\n")
print("Detailed Classification Report:")
print(classification_report(y_test, predictions))

# 6. Save the trained model
joblib.dump(model, 'src/phishing_model.pkl')
print("\nModel saved successfully as phishing_model.pkl!")