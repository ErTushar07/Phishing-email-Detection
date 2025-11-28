"""
Script to download required NLTK data for the Phishing Email Detection System.
"""

import nltk

def download_nltk_data():
    """Download all required NLTK data."""
    print("Downloading required NLTK data...")
    
    # List of required NLTK data packages
    required_data = [
        'punkt',
        'punkt_tab',
        'stopwords',
        'wordnet',
        'omw-1.4'
    ]
    
    for item in required_data:
        try:
            print(f"Downloading {item}...")
            nltk.download(item, quiet=True)
            print(f"Successfully downloaded {item}")
        except Exception as e:
            print(f"Failed to download {item}: {e}")
    
    print("NLTK data download completed!")

if __name__ == "__main__":
    download_nltk_data()