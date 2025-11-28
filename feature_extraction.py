"""
Feature extraction module for the Phishing Email Detection System.
Extracts various features from email content for classification.
"""

import re
import urllib.parse
from typing import Dict, List, Tuple
import socket

class FeatureExtractor:
    """Class for extracting features from email content."""
    
    def __init__(self):
        """Initialize the feature extractor with predefined patterns."""
        # Suspicious keywords commonly found in phishing emails
        self.suspicious_keywords = [
            'urgent', 'verify', 'click here', 'confirm', 'update', 'account',
            'password', 'security', 'suspicious', 'limited time', 'act now',
            'exclusive deal', 'money back', 'refund', 'win', 'winner', 'prize',
            'congratulations', 'free', 'offer', 'deal', 'bonus', 'risk-free',
            'guarantee', 'no obligation', 'cancel', 'terminate', 'alert'
        ]
        
        # Common URL shortening services
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly',
            'is.gd', 'soo.gd', 's.id', 'bl.ink', 'cutt.ly', 'rb.gy'
        ]
        
        # Known malicious domains (in a real system, this would be much larger)
        self.known_malicious_domains = [
            '163.com.cn', 'fake-bank.com', 'phishing-site.org', 'scam-domain.net'
        ]
        
    def extract_suspicious_keywords(self, text: str) -> int:
        """
        Count the number of suspicious keywords in the text.
        
        Args:
            text (str): The text to analyze
            
        Returns:
            int: Number of suspicious keywords found
        """
        count = 0
        text_lower = text.lower()
        for keyword in self.suspicious_keywords:
            count += text_lower.count(keyword.lower())
        return count
    
    def extract_url_features(self, text: str) -> Dict[str, int]:
        """
        Extract URL-related features from the text.
        
        Args:
            text (str): The text to analyze
            
        Returns:
            Dict[str, int]: Dictionary containing URL features
        """
        # Find all URLs in the text
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        urls = re.findall(url_pattern, text)
        
        # Check for IP-based URLs
        ip_url_count = 0
        short_url_count = 0
        
        for url in urls:
            try:
                parsed_url = urllib.parse.urlparse(url)
                hostname = parsed_url.hostname
                
                # Check if it's an IP address
                if hostname:
                    socket.inet_aton(hostname)
                    ip_url_count += 1
            except (socket.error, ValueError):
                # Not an IP address
                pass
            
            # Check if it's a shortened URL
            for shortener in self.url_shorteners:
                if shortener in url:
                    short_url_count += 1
                    break
        
        return {
            'total_urls': len(urls),
            'ip_based_urls': ip_url_count,
            'shortened_urls': short_url_count
        }
    
    def extract_html_js_features(self, text: str) -> Dict[str, int]:
        """
        Extract HTML and JavaScript features from the text.
        
        Args:
            text (str): The text to analyze
            
        Returns:
            Dict[str, int]: Dictionary containing HTML/JS features
        """
        html_tags_pattern = r'<[^>]+>'
        js_pattern = r'(javascript:|eval\(|script[^>]*>|onload=|onclick=)'
        
        html_tags_count = len(re.findall(html_tags_pattern, text, re.IGNORECASE))
        js_count = len(re.findall(js_pattern, text, re.IGNORECASE))
        
        return {
            'html_tags': html_tags_count,
            'javascript': js_count
        }
    
    def extract_domain_reputation(self, sender_email: str) -> Dict[str, int]:
        """
        Extract domain reputation features from sender email.
        
        Args:
            sender_email (str): The sender's email address
            
        Returns:
            Dict[str, int]: Dictionary containing domain reputation features
        """
        if '@' not in sender_email:
            return {'suspicious_domain': 1}
        
        domain = sender_email.split('@')[1].lower()
        
        # Check if domain is in known malicious domains
        suspicious = 1 if domain in self.known_malicious_domains else 0
        
        return {
            'suspicious_domain': suspicious
        }
    
    def extract_all_features(self, email_text: str, sender_email: str = "") -> Dict[str, int]:
        """
        Extract all features from the email content.
        
        Args:
            email_text (str): The email content
            sender_email (str): The sender's email address (optional)
            
        Returns:
            Dict[str, int]: Dictionary containing all extracted features
        """
        features = {}
        
        # Extract suspicious keywords
        features['suspicious_keywords'] = self.extract_suspicious_keywords(email_text)
        
        # Extract URL features
        url_features = self.extract_url_features(email_text)
        features.update(url_features)
        
        # Extract HTML/JS features
        html_js_features = self.extract_html_js_features(email_text)
        features.update(html_js_features)
        
        # Extract domain reputation if sender email is provided
        if sender_email:
            domain_features = self.extract_domain_reputation(sender_email)
            features.update(domain_features)
        else:
            features['suspicious_domain'] = 0
        
        return features

def extract_features_from_email(email_text: str, sender_email: str = "") -> Dict[str, int]:
    """
    Convenience function to extract features from email content.
    
    Args:
        email_text (str): The email content
        sender_email (str): The sender's email address (optional)
        
    Returns:
        Dict[str, int]: Dictionary containing all extracted features
    """
    extractor = FeatureExtractor()
    return extractor.extract_all_features(email_text, sender_email)