"""
Main application script for the Phishing Email Detection System.
Ties all modules together and provides a unified interface.
"""

import argparse
import sys
import os
from typing import Dict, Any

from preprocessing import preprocess_email_content
from feature_extraction import extract_features_from_email
from model_training import ModelTrainer
from prediction import EmailPredictor
from logger import PhishingLogger

def train_model(dataset_path: str = None):
    """
    Train the phishing detection model.
    
    Args:
        dataset_path (str): Path to training dataset (CSV format)
    """
    print("Training phishing detection model...")
    
    trainer = ModelTrainer()
    
    # Load data
    X_raw, y = trainer.load_data(dataset_path or 'email_data.csv')
    
    # Prepare features
    X = trainer.prepare_features(X_raw)
    
    # Train models
    trainer.train_models(X, y)
    
    # Get best model
    best_model_name, best_model = trainer.get_best_model()
    
    # Save the best model
    model_path = trainer.save_model(best_model, best_model_name)
    
    # Display results
    print(f"\nTraining completed!")
    print(f"Best model: {best_model_name}")
    print(f"Model saved to: {model_path}")
    print("\nEvaluation Results:")
    for model_name, metrics in trainer.evaluation_results.items():
        print(f"\n{model_name}:")
        print(f"  Accuracy: {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall: {metrics['recall']:.4f}")
        print(f"  F1-Score: {metrics['f1_score']:.4f}")
    
    return model_path

def classify_email(email_text: str, sender_email: str = "", model_path: str = None):
    """
    Classify an email as phishing or legitimate.
    
    Args:
        email_text (str): The email content to classify
        sender_email (str): The sender's email address
        model_path (str): Path to the trained model
        
    Returns:
        Dict[str, Any]: Classification results
    """
    # Initialize predictor
    predictor = EmailPredictor(model_path)
    
    # Make prediction
    result = predictor.predict_email(email_text, sender_email)
    
    # Log result
    logger = PhishingLogger('csv')
    logger.log_result(result)
    
    return result

def display_result(result: Dict[str, Any]):
    """
    Display the classification result in a formatted way.
    
    Args:
        result (Dict[str, Any]): Classification result
    """
    print("\n" + "="*50)
    print("PHISHING EMAIL DETECTION RESULT")
    print("="*50)
    print(f"Classification: {result['classification'].upper()}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Sender: {result['sender']}")
    
    print("\nFeature Analysis:")
    features = result['features']
    print(f"  Suspicious Keywords: {features.get('suspicious_keywords', 0)}")
    print(f"  Total URLs: {features.get('total_urls', 0)}")
    print(f"  IP-based URLs: {features.get('ip_based_urls', 0)}")
    print(f"  Shortened URLs: {features.get('shortened_urls', 0)}")
    print(f"  HTML Tags: {features.get('html_tags', 0)}")
    print(f"  JavaScript: {features.get('javascript', 0)}")
    print(f"  Suspicious Domain: {features.get('suspicious_domain', 0)}")
    print("="*50)

def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(description='Phishing Email Detection System')
    parser.add_argument('--train', action='store_true', help='Train the model')
    parser.add_argument('--classify', action='store_true', help='Classify an email')
    parser.add_argument('--text', type=str, help='Email text to classify')
    parser.add_argument('--file', type=str, help='Path to file containing email text')
    parser.add_argument('--sender', type=str, default='', help='Sender email address')
    parser.add_argument('--dataset', type=str, help='Path to training dataset (CSV)')
    parser.add_argument('--model', type=str, default='logistic_regression_model.pkl', 
                        help='Path to trained model file')
    
    args = parser.parse_args()
    
    # If no arguments provided, show help
    if not any([args.train, args.classify]):
        parser.print_help()
        return
    
    # Training mode
    if args.train:
        model_path = train_model(args.dataset)
        return
    
    # Classification mode
    if args.classify:
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
            print("Please provide either --text or --file argument for classification.")
            sys.exit(1)
        
        # Classify email
        result = classify_email(email_text, args.sender, args.model)
        
        # Display result
        display_result(result)

if __name__ == "__main__":
    main()