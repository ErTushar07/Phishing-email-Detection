"""
Model training module for the Phishing Email Detection System.
Trains machine learning models using scikit-learn to classify emails.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import os
from typing import Dict, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

class ModelTrainer:
    """Class for training machine learning models for phishing email detection."""
    
    def __init__(self):
        """Initialize the model trainer with default models."""
        self.models = {
            'logistic_regression': LogisticRegression(random_state=42, max_iter=1000),
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'naive_bayes': MultinomialNB()
        }
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        self.trained_models = {}
        self.evaluation_results = {}
        
    def load_data(self, csv_file_path: str) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Load training data from CSV file.
        
        Args:
            csv_file_path (str): Path to the CSV file containing email data
            
        Returns:
            Tuple[pd.DataFrame, pd.Series]: Features and labels
        """
        # In a real implementation, this would load actual email data
        # For now, we'll create a placeholder that shows the expected format
        try:
            data = pd.read_csv(csv_file_path)
            # Assuming columns: 'email_text', 'label' (0 for legitimate, 1 for phishing)
            X = data['email_text']
            y = data['label']
            return X, y
        except FileNotFoundError:
            print(f"CSV file {csv_file_path} not found. Creating sample data for demonstration.")
            return self._create_sample_data()
    
    def _create_sample_data(self) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Create sample data for demonstration purposes.
        
        Returns:
            Tuple[pd.DataFrame, pd.Series]: Sample features and labels
        """
        # Sample legitimate emails
        legitimate_emails = [
            "Hi John, let's meet for coffee tomorrow at 3pm. Best regards, Mary",
            "Your monthly newsletter subscription has been confirmed. Thank you!",
            "Meeting notes from today's project discussion are attached.",
            "Your order #12345 has been shipped and will arrive in 2-3 business days.",
            "Reminder: Team lunch is scheduled for Friday at noon in the conference room."
        ]
        
        # Sample phishing emails
        phishing_emails = [
            "URGENT: Verify your account now or it will be suspended immediately!",
            "Congratulations! You've won $1000! Click here to claim your prize now!",
            "Security Alert: Login to your bank account to verify recent activity.",
            "Your password has expired. Update it now by clicking this link: http://192.168.1.1/login",
            "Act now! Limited time offer - Get rich quick with no risk guarantee!"
        ]
        
        # Combine and create labels
        emails = legitimate_emails + phishing_emails
        labels = [0] * len(legitimate_emails) + [1] * len(phishing_emails)
        
        return pd.Series(emails), pd.Series(labels)
    
    def prepare_features(self, X: pd.Series) -> np.ndarray:
        """
        Prepare features using TF-IDF vectorization.
        
        Args:
            X (pd.Series): Raw email text data
            
        Returns:
            np.ndarray: Vectorized features
        """
        # Fit and transform the text data
        X_vectorized = self.vectorizer.fit_transform(X)
        return X_vectorized.toarray()
    
    def train_models(self, X: np.ndarray, y: pd.Series) -> Dict[str, Any]:
        """
        Train all available models.
        
        Args:
            X (np.ndarray): Feature matrix
            y (pd.Series): Labels
            
        Returns:
            Dict[str, Any]: Trained models
        """
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        for name, model in self.models.items():
            print(f"Training {name}...")
            model.fit(X_train, y_train)
            self.trained_models[name] = model
            
            # Evaluate the model
            y_pred = model.predict(X_test)
            self.evaluation_results[name] = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, zero_division=0),
                'recall': recall_score(y_test, y_pred, zero_division=0),
                'f1_score': f1_score(y_test, y_pred, zero_division=0),
                'confusion_matrix': confusion_matrix(y_test, y_pred)
            }
            
            print(f"{name} - Accuracy: {self.evaluation_results[name]['accuracy']:.4f}")
        
        return self.trained_models
    
    def get_best_model(self) -> Tuple[str, Any]:
        """
        Get the best performing model based on F1 score.
        
        Returns:
            Tuple[str, Any]: Name and model object of the best model
        """
        if not self.evaluation_results:
            raise ValueError("No models have been evaluated yet.")
        
        best_model_name = max(
            self.evaluation_results.keys(),
            key=lambda x: self.evaluation_results[x]['f1_score']
        )
        best_model = self.trained_models[best_model_name]
        
        return best_model_name, best_model
    
    def save_model(self, model, model_name: str, filepath: str = None) -> str:
        """
        Save the trained model to disk.
        
        Args:
            model: Trained model object
            model_name (str): Name of the model
            filepath (str): Path to save the model (optional)
            
        Returns:
            str: Path where the model was saved
        """
        if filepath is None:
            filepath = f"{model_name}_model.pkl"
        
        # Save both the model and vectorizer
        model_data = {
            'model': model,
            'vectorizer': self.vectorizer
        }
        
        joblib.dump(model_data, filepath)
        print(f"Model saved to {filepath}")
        return filepath
    
    def load_model(self, filepath: str) -> Dict[str, Any]:
        """
        Load a trained model from disk.
        
        Args:
            filepath (str): Path to the saved model
            
        Returns:
            Dict[str, Any]: Loaded model and vectorizer
        """
        model_data = joblib.load(filepath)
        return model_data

def train_phishing_detection_model(csv_file_path: str = None) -> Tuple[Any, str, Dict[str, Any]]:
    """
    Convenience function to train the phishing detection model.
    
    Args:
        csv_file_path (str): Path to training data CSV file (optional)
        
    Returns:
        Tuple[Any, str, Dict[str, Any]]: Best model, its name, and evaluation results
    """
    trainer = ModelTrainer()
    
    # Load data
    X_raw, y = trainer.load_data(csv_file_path or 'email_data.csv')
    
    # Prepare features
    X = trainer.prepare_features(X_raw)
    
    # Train models
    trainer.train_models(X, y)
    
    # Get best model
    best_model_name, best_model = trainer.get_best_model()
    
    # Save the best model
    trainer.save_model(best_model, best_model_name)
    
    return best_model, best_model_name, trainer.evaluation_results

if __name__ == "__main__":
    # Example usage
    print("Training phishing detection models...")
    model, model_name, results = train_phishing_detection_model()
    print(f"\nBest model: {model_name}")
    print(f"Evaluation results: {results[model_name]}")