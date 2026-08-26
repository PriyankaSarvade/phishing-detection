import pandas as pd
import os

def load_and_preprocess_data(file_path):
    # 1. Load dataset
    df = pd.read_csv(file_path)
    
    # 2. Drop missing values 
    df.dropna(inplace=True)

    # 3. Remove duplicate rows 
    df.drop_duplicates(inplace=True)
    
    # 4. Clean the URL text 
    # (Checking if 'domain' column exists first to prevent errors)
    if 'domain' in df.columns:
        df['domain'] = df['domain'].str.strip().str.lower()
    
    # 5. Map labels: benign -> 0, malicious/phishing -> 1
    label_mapping = {
        'benign': 0,
        'phishing': 1,
        'defacement': 1,
        'malware': 1
    }
    
    # Check if the column is named 'type' or 'label' in your CSV
    target_col = 'type' if 'type' in df.columns else 'label'
    
    # Only map if the data is still text (prevents crashing if it's already 0s and 1s)
    if df[target_col].dtype == 'object':
        df['label'] = df[target_col].map(label_mapping)
    
    return df

if __name__ == "__main__":
    # Define file paths
    input_path = "dataset/phishing_dataset.csv"
    output_path = "dataset/cleaned_phishing_dataset.csv"
    
    # Run the cleaning function
    data = load_and_preprocess_data(input_path)
    
    # --- NEW: Sanity Check ---
    print("\n--- Data Cleaning Complete ---")
    print(f"Total rows remaining: {len(data)}")
    print("\nClass Distribution:")
    print(data['label'].value_counts())
    
    # --- NEW: Save the File ---
    # Create the dataset folder if it doesn't exist
    os.makedirs("dataset", exist_ok=True) 
    
    # Save to a new CSV without keeping the row numbers (index=False)
    data.to_csv(output_path, index=False)
    print(f"\nSuccess! Cleaned data saved to {output_path}")