import pandas as pd

def load_and_preprocess_data(file_path):
    # Load dataset
    df = pd.read_csv(file_path)
    
    # Drop missing values if any exist
    df.dropna(inplace=True)
    
    # Map labels: benign -> 0, malicious/phishing -> 1
    # Adjust mapping based on unique values in your dataset
    label_mapping = {
        'benign': 0,
        'phishing': 1,
        'defacement': 1,
        'malware': 1
    }
    df['label'] = df['type'].map(label_mapping)
    
    return df

if __name__ == "__main__":
    dataset_path = "phishing-detection/dataset/phishing_dataset.csv"
    data = load_and_preprocess_data(dataset_path)
    print("Dataset successfully loaded and preprocessed!")
    print(data.head())