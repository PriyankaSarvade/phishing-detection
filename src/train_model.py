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

from sklearn.model_selection import GridSearchCV

# 4. Train Random Forest Model using Hyperparameter Tuning
print("Initiating Hyperparameter Tuning (This may take a few minutes)...")
param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [None, 10, 20],
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1, 2]
}

grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=5, verbose=1, n_jobs=-1)
grid_search.fit(X_train, y_train)

print(f"\nBest Model Configuration: {grid_search.best_params_}")

# We reassign the best result back to 'model' so your existing evaluation code below still works
model = grid_search.best_estimator_ 

# Extract Feature Importance
print("\n--- Feature Importance Ranking ---")
feature_importances = pd.DataFrame({
    'Feature': X.columns,
    'Importance': model.feature_importances_
}).sort_values(by='Importance', ascending=False)
print(feature_importances.to_string(index=False))

# Overwrite your model file with this optimized version
joblib.dump(model, 'src/phishing_model.pkl')
print("\nOptimized model saved successfully as phishing_model.pkl!")

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Assuming your model is named 'model', and your test data is X_test and y_test
print("--- Model Evaluation ---")

# 1. Make predictions on the hidden testing data
predictions = model.predict(X_test)

# 2. Calculate overall accuracy
accuracy = accuracy_score(y_test, predictions)
print(f"Overall Accuracy: {accuracy * 100:.2f}%\n")

# 3. Print the Confusion Matrix (Shows True Positives, False Positives, etc.)
print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))
print("\n")

# 4. Print the detailed Classification Report
print("Classification Report:")
print(classification_report(y_test, predictions, target_names=['Legitimate (0)', 'Phishing (1)']))