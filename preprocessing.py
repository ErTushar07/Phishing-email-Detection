"""
Text preprocessing module for the Phishing Email Detection System.
Handles tokenization, stopword removal, and lemmatization of email content.
"""

import re
import string
from typing import List
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

try:
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('wordnet')

class TextPreprocessor:
    """Class for preprocessing email text content."""
    
    def __init__(self):
        """Initialize the preprocessor with required NLTK components."""
        self.stop_words = set(stopwords.words('english'))
        self.lemmatizer = WordNetLemmatizer()
        
    def tokenize(self, text: str) -> List[str]:
        """
        Tokenize the input text into words.
        
        Args:
            text (str): The text to tokenize
            
        Returns:
            List[str]: List of tokens
        """
        # Convert to lowercase
        text = text.lower()
        
        # Remove punctuation
        text = text.translate(str.maketrans('', '', string.punctuation))
        
        # Tokenize
        tokens = word_tokenize(text)
        
        return tokens
    
    def remove_stopwords(self, tokens: List[str]) -> List[str]:
        """
        Remove stopwords from the token list.
        
        Args:
            tokens (List[str]): List of tokens
            
        Returns:
            List[str]: Tokens with stopwords removed
        """
        filtered_tokens = [token for token in tokens if token not in self.stop_words]
        return filtered_tokens
    
    def lemmatize(self, tokens: List[str]) -> List[str]:
        """
        Lemmatize the tokens to their base form.
        
        Args:
            tokens (List[str]): List of tokens
            
        Returns:
            List[str]: Lemmatized tokens
        """
        lemmatized_tokens = [self.lemmatizer.lemmatize(token) for token in tokens]
        return lemmatized_tokens
    
    def preprocess(self, text: str) -> List[str]:
        """
        Complete preprocessing pipeline: tokenize -> remove stopwords -> lemmatize.
        
        Args:
            text (str): The text to preprocess
            
        Returns:
            List[str]: Preprocessed tokens
        """
        tokens = self.tokenize(text)
        tokens = self.remove_stopwords(tokens)
        tokens = self.lemmatize(tokens)
        return tokens

def preprocess_email_content(email_text: str) -> List[str]:
    """
    Convenience function to preprocess email content.
    
    Args:
        email_text (str): The email content to preprocess
        
    Returns:
        List[str]: Preprocessed tokens
    """
    preprocessor = TextPreprocessor()
    return preprocessor.preprocess(email_text)