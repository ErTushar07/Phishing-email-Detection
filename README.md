# Phishing Email Detection System

A Python-based machine learning system for detecting phishing emails using natural language processing and feature extraction techniques.

## Features

1. **Text Preprocessing**: Tokenization, stopword removal, and lemmatization
2. **Feature Extraction**: 
   - Suspicious keywords detection
   - URL pattern analysis (IP-based links, shortened URLs)
   - Sender domain reputation checking
   - HTML/JavaScript content detection
3. **Machine Learning Models**: Logistic Regression, Random Forest, and Naive Bayes classifiers
4. **Model Evaluation**: Accuracy, precision, recall, F1-score, and confusion matrix
5. **Model Persistence**: Save/load trained models with joblib
6. **Command-Line Interface**: Easy email classification from command line
7. **Logging**: Record results with timestamps in CSV/JSON format
8. **Modular Design**: Separate modules for preprocessing, feature extraction, training, and prediction

## Requirements

- Python 3.7+
- NLTK
- scikit-learn
- pandas
- numpy
- joblib

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/ErTushar07/phishing-email-detection.git
   cd phishing-email-detection
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Download NLTK data:
   ```
   python download_nltk_data.py
   ```

## Usage

### Training the Model

To train the model with the sample dataset:
```bash
python main.py --train --dataset sample_dataset.csv
```

### Classifying Emails

#### From Command Line Text:
```bash
python main.py --classify --text "Congratulations! You've won $1000! Click here to claim your prize now!" --sender "scammer@fake-bank.com"
```

#### From File:
```bash
python main.py --classify --file email.txt --sender "sender@example.com"
```

### Using the Prediction Module Directly:
```python
from prediction import EmailPredictor

predictor = EmailPredictor('logistic_regression_model.pkl')
result = predictor.predict_email(
    "URGENT: Verify your account now or it will be suspended!",
    "suspicious@scam-domain.net"
)
print(result)
```

## Project Structure

```
phishing-email-detection/
├── main.py                 # Main application script
├── preprocessing.py         # Text preprocessing module
├── feature_extraction.py    # Feature extraction module
├── model_training.py        # Model training module
├── prediction.py            # Prediction and CLI module
├── logger.py               # Logging module
├── download_nltk_data.py    # NLTK data downloader
├── test_system.py          # System testing script
├── requirements.txt        # Python dependencies
├── sample_dataset.csv      # Sample training data
└── README.md              # This file
```

## How It Works

1. **Preprocessing**: Email text is cleaned, tokenized, and normalized
2. **Feature Extraction**: Multiple features are extracted including:
   - Count of suspicious keywords
   - URL analysis (IP addresses, shortened links)
   - HTML/JavaScript content detection
   - Domain reputation checking
3. **Classification**: Machine learning models classify emails as phishing (1) or legitimate (0)
4. **Evaluation**: Models are evaluated using standard metrics
5. **Logging**: Results are logged with timestamps for auditing

## Dataset Format

The training dataset should be a CSV file with two columns:
- `email_text`: The content of the email
- `label`: 1 for phishing emails, 0 for legitimate emails

Example:
```csv
email_text,label
"Congratulations! You've won $1000! Click here!",1
"Hi John, let's meet for coffee tomorrow.",0
```

## Model Performance

The system trains three models and selects the best one based on F1-score:
- Logistic Regression
- Random Forest
- Naive Bayes

With the provided sample dataset, the system achieves:
- Accuracy: ~50% (limited by small dataset size)
- Precision: Varies by model
- Recall: Varies by model
- F1-Score: Used to select the best model

In production with a larger, more balanced dataset, performance would be significantly improved.

## Feature Extraction Details

### Suspicious Keywords
The system checks for common phishing terms such as:
- "urgent", "verify", "click here", "confirm", "update"
- "password", "security", "suspicious", "limited time"
- "act now", "exclusive deal", "money back", "refund"
- "win", "winner", "prize", "congratulations", "free"
- And many others

### URL Analysis
- Detects IP-based URLs (e.g., http://192.168.1.1/login)
- Identifies shortened URLs from services like bit.ly, tinyurl.com
- Counts total URLs in the email

### Domain Reputation
- Checks sender domain against a list of known malicious domains
- Flags suspicious domain patterns

### HTML/JavaScript Detection
- Counts HTML tags in the email
- Detects JavaScript code patterns that are common in phishing

## Logging

Results are automatically logged to `phishing_detection_log.csv` with:
- Timestamp of classification
- Sender email address
- Classification result (phishing/legitimate)
- Confidence score
- All extracted features

## Testing

Run the comprehensive test suite:
```bash
python test_system.py
```

This will test the system with various email examples and log the results.

## Limitations

1. The sample dataset is small and for demonstration purposes only
2. Domain reputation checking uses a hardcoded list (should be expanded in production)
3. Feature extraction could be enhanced with more sophisticated NLP techniques
4. The system focuses on text content and may miss image-based phishing attempts
5. Performance is limited by the small training dataset size

## Improving Performance

To improve the system's performance:
1. Use a larger, more balanced training dataset
2. Add more sophisticated features (e.g., email header analysis)
3. Implement ensemble methods combining multiple models
4. Regularly update the domain reputation database
5. Add more advanced NLP techniques (e.g., word embeddings)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

ErTushar07