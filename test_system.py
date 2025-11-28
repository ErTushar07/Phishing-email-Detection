"""
Test script for the Phishing Email Detection System.
Demonstrates the capabilities of the system with various examples.
"""

from prediction import EmailPredictor
from logger import PhishingLogger

def test_system():
    """Test the phishing email detection system with various examples."""
    print("Testing Phishing Email Detection System")
    print("=" * 50)
    
    # Initialize predictor
    predictor = EmailPredictor('logistic_regression_model.pkl')
    
    # Test cases: (email_text, sender, expected_classification)
    test_cases = [
        (
            "Congratulations! You've won $1000! Click here to claim your prize now! http://bit.ly/claimprize",
            "scammer@fake-bank.com",
            "phishing"
        ),
        (
            "Hi John, I hope you're doing well. Let's schedule a meeting for next week to discuss the project. Please let me know your availability.",
            "colleague@company.com",
            "legitimate"
        ),
        (
            "URGENT: Your account will be suspended unless you verify your information immediately. Click here to login: http://192.168.1.10/login",
            "security@fake-paypal.com",
            "phishing"
        ),
        (
            "Thank you for your purchase. Your order #4589 has been shipped and will arrive within 3-5 business days. Tracking number: XYZ123456",
            "orders@amazon.com",
            "legitimate"
        ),
        (
            "FINAL NOTICE: Your warranty is about to expire. Extend your coverage now to protect your investment. Act fast before it's too late!",
            "support@warranty-service.net",
            "phishing"
        )
    ]
    
    # Initialize logger
    logger = PhishingLogger('csv')
    
    # Test each case
    for i, (email_text, sender, expected) in enumerate(test_cases, 1):
        print(f"\nTest Case {i}:")
        print(f"Expected: {expected.upper()}")
        
        # Make prediction
        result = predictor.predict_email(email_text, sender)
        
        # Display result
        print(f"Actual: {result['classification'].upper()}")
        print(f"Confidence: {result['confidence']:.4f}")
        print(f"Sender: {result['sender']}")
        
        # Log result
        logger.log_result(result)
        
        # Check if prediction matches expectation
        match = "✓" if result['classification'] == expected else "✗"
        print(f"Match: {match}")
        
        # Show key features
        features = result['features']
        print("Key Features:")
        print(f"  Suspicious Keywords: {features.get('suspicious_keywords', 0)}")
        print(f"  URLs: {features.get('total_urls', 0)}")
        print(f"  Suspicious Domain: {features.get('suspicious_domain', 0)}")
    
    print("\n" + "=" * 50)
    print("Testing completed. Results have been logged to phishing_detection_log.csv")

if __name__ == "__main__":
    test_system()