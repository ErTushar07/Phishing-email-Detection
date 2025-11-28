"""
Logging module for the Phishing Email Detection System.
Logs results with timestamp, sender info, and classification outcome.
"""

import json
import csv
import os
from datetime import datetime
from typing import Dict, Any

class PhishingLogger:
    """Class for logging phishing detection results."""
    
    def __init__(self, log_format: str = 'csv'):
        """
        Initialize the logger.
        
        Args:
            log_format (str): Format for logging ('csv' or 'json')
        """
        self.log_format = log_format
        self.csv_file = 'phishing_detection_log.csv'
        self.json_file = 'phishing_detection_log.json'
        
        # Create CSV file with headers if it doesn't exist
        if log_format == 'csv' and not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'sender', 'classification', 'confidence', 
                    'suspicious_keywords', 'total_urls', 'ip_based_urls',
                    'shortened_urls', 'html_tags', 'javascript', 'suspicious_domain'
                ])
    
    def log_result(self, result: Dict[str, Any]):
        """
        Log a detection result.
        
        Args:
            result (Dict[str, Any]): Detection result to log
        """
        timestamp = datetime.now().isoformat()
        
        if self.log_format == 'csv':
            self._log_to_csv(result, timestamp)
        elif self.log_format == 'json':
            self._log_to_json(result, timestamp)
        else:
            raise ValueError("Unsupported log format. Use 'csv' or 'json'.")
    
    def _log_to_csv(self, result: Dict[str, Any], timestamp: str):
        """
        Log result to CSV file.
        
        Args:
            result (Dict[str, Any]): Detection result to log
            timestamp (str): ISO formatted timestamp
        """
        features = result.get('features', {})
        
        row = [
            timestamp,
            result.get('sender', ''),
            result.get('classification', ''),
            result.get('confidence', 0.0),
            features.get('suspicious_keywords', 0),
            features.get('total_urls', 0),
            features.get('ip_based_urls', 0),
            features.get('shortened_urls', 0),
            features.get('html_tags', 0),
            features.get('javascript', 0),
            features.get('suspicious_domain', 0)
        ]
        
        with open(self.csv_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(row)
    
    def _log_to_json(self, result: Dict[str, Any], timestamp: str):
        """
        Log result to JSON file.
        
        Args:
            result (Dict[str, Any]): Detection result to log
            timestamp (str): ISO formatted timestamp
        """
        log_entry = {
            'timestamp': timestamp,
            'sender': result.get('sender', ''),
            'classification': result.get('classification', ''),
            'confidence': result.get('confidence', 0.0),
            'features': result.get('features', {})
        }
        
        # Read existing data
        data = []
        if os.path.exists(self.json_file):
            with open(self.json_file, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
        
        # Append new entry
        data.append(log_entry)
        
        # Write back to file
        with open(self.json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

def log_detection_result(result: Dict[str, Any], log_format: str = 'csv'):
    """
    Convenience function to log a detection result.
    
    Args:
        result (Dict[str, Any]): Detection result to log
        log_format (str): Format for logging ('csv' or 'json')
    """
    logger = PhishingLogger(log_format)
    logger.log_result(result)

if __name__ == "__main__":
    # Example usage
    sample_result = {
        'sender': 'test@example.com',
        'classification': 'phishing',
        'confidence': 0.95,
        'features': {
            'suspicious_keywords': 3,
            'total_urls': 2,
            'ip_based_urls': 1,
            'shortened_urls': 1,
            'html_tags': 5,
            'javascript': 2,
            'suspicious_domain': 1
        }
    }
    
    log_detection_result(sample_result, 'csv')
    log_detection_result(sample_result, 'json')
    print("Sample results logged to CSV and JSON files.")