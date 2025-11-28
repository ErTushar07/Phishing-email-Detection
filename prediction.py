"""
Prediction module for the Phishing Email Detection System.
Handles classification of new emails and provides a command-line interface.
"""

import joblib
import numpy as np
import argparse
import sys
from typing import Dict, Any, Tuple
import os

from preprocessing import preprocess_email_content
from feature_extraction import extract_features_from_email

class EmailPredictor:
    """Class for predicting whether an email is phishing or legitimate."""
    
    def __init__(self, model_path: str = None):
        """
        Initialize the predictor with a trained model.
        
        Args:
            model_path (str): Path to the saved model file
        """
        if model_path and os.path.exists(model_path):
            self.model_data = joblib.load(model_path)
            self.model = self.model_data['model']
            self.vectorizer = self.model_data['vectorizer']
        else:
            # If no model is provided, create a placeholder
            # In a real scenario, this would raise an exception
            print("Warning: No trained model found. Using placeholder.")
            self.model = None
            self.vectorizer = None
    
    def predict_email(self, email_text: str, sender_email: str = "") -> Dict[str, Any]:
        """
        Predict whether an email is phishing or legitimate.
        
        Args:
            email_text (str): The email content to classify
            sender_email (str): The sender's email address (optional)
            
        Returns:
            Dict[str, Any]: Prediction results including classification and confidence
        """
        if self.model is None or self.vectorizer is None:
            # Return a placeholder result if no model is loaded
            return {
                'classification': 'unknown',
                'confidence': 0.0,
                'features': {},
                'sender': sender_email
            }
        
        # Preprocess the email text
        preprocessed_text = ' '.join(preprocess_email_content(email_text))
        
        # Vectorize the text
        text_vector = self.vectorizer.transform([preprocessed_text]).toarray()
        
        # Make prediction
        prediction = self.model.predict(text_vector)[0]
        probabilities = self.model.predict_proba(text_vector)[0]
        
        # Extract features for additional analysis
        features = extract_features_from_email(email_text, sender_email)
        
        # Determine confidence (probability of predicted class)
        confidence = max(probabilities)
        
        # Map prediction to label
        classification = 'phishing' if prediction == 1 else 'legitimate'
        
        return {
            'classification': classification,
            'confidence': float(confidence),
            'features': features,
            'sender': sender_email
        }
    
    def batch_predict(self, emails: list) -> list:
        """
        Predict classifications for a batch of emails.
        
        Args:
            emails (list): List of dictionaries with 'text' and 'sender' keys
            
        Returns:
            list: List of prediction results
        """
        results = []
        for email in emails:
            result = self.predict_email(email['text'], email.get('sender', ''))
            results.append(result)
        return results

def main_cli():
    """Main command-line interface for the phishing email detector."""
    parser = argparse.ArgumentParser(description='Phishing Email Detection System')
    parser.add_argument('--text', type=str, help='Email text to classify')
    parser.add_argument('--file', type=str, help='Path to file containing email text')
    parser.add_argument('--sender', type=str, default='', help='Sender email address')
    parser.add_argument('--model', type=str, default='logistic_regression_model.pkl', 
                        help='Path to trained model file')
    
    args = parser.parse_args()
    
    # Initialize predictor
    predictor = EmailPredictor(args.model)
    
    # Get email text
    email_text = ""
    if args.text:
        email_text = args.text
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                email_text = f.read()
        except FileNotFoundError:
            print(f"Error: File {args.file} not found.")
            sys.exit(1)
    else:
        print("Please provide either --text or --file argument.")
        parser.print_help()
        sys.exit(1)
    
    # Make prediction
    result = predictor.predict_email(email_text, args.sender)
    
    # Display results
    print("\n=== Phishing Email Detection Result ===")
    print(f"Classification: {result['classification'].upper()}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Sender: {result['sender']}")
    print("\nFeature Analysis:")
    for feature, value in result['features'].items():
        print(f"  {feature}: {value}")

if __name__ == "__main__":
    main_cli()