"""
Header analyzer module for email header analysis.
"""

import re
from typing import Dict, Any
from email.message import EmailMessage
from .base_analyzer import BaseAnalyzer


class HeaderAnalyzer(BaseAnalyzer):
    """
    Analyzer for email headers and spoof detection.
    """
    
    def __init__(self, investigation_mode: bool = False):
        super().__init__(investigation_mode)
        self.mail_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    
    def analyze(self, msg: EmailMessage, **kwargs) -> Dict[str, Any]:
        """
        Analyze email headers for suspicious indicators.
        
        Args:
            msg: Email message object
            
        Returns:
            Dictionary containing header analysis results
        """
        data = self._create_data_structure("Headers")
        
        # Extract all headers
        for key, value in msg.items():
            clean_value = str(value).replace('\t', '').replace('\n', '')
            data["Headers"]["Data"][key.lower()] = clean_value
        
        # Handle multiple 'Received' headers specially
        if data["Headers"]["Data"].get('received'):
            received_headers = msg.get_all('Received') or []
            data["Headers"]["Data"]['received'] = received_headers
        
        # Perform investigation analysis if requested
        if self.investigation_mode:
            self._investigate_headers(data, msg)
        
        self.results = data
        return data
    
    def _investigate_headers(self, data: Dict[str, Any], msg: EmailMessage) -> None:
        """
        Perform detailed investigation of headers.
        
        Args:
            data: Data structure to populate
            msg: Email message object
        """
        # Investigate sender IP addresses
        self._investigate_sender_ips(data)
        
        # Check for email spoofing
        self._check_spoofing(data)
    
    def _investigate_sender_ips(self, data: Dict[str, Any]) -> None:
        """
        Extract and investigate sender IP addresses.
        
        Args:
            data: Data structure to populate
        """
        # Check for X-Sender-IP header
        sender_ip = data["Headers"]["Data"].get("x-sender-ip")
        if sender_ip:
            self._add_investigation_links(sender_ip, data, "Headers", "X-Sender-IP")
    
    def _check_spoofing(self, data: Dict[str, Any]) -> None:
        """
        Check for potential email spoofing by comparing Reply-To and From headers.
        
        Args:
            data: Data structure to populate
        """
        reply_to = data["Headers"]["Data"].get("reply-to", "")
        from_header = data["Headers"]["Data"].get("from", "")
        
        if not reply_to or not from_header:
            return
        
        # Extract email addresses using regex
        replyto_matches = re.findall(self.mail_regex, reply_to)
        mailfrom_matches = re.findall(self.mail_regex, from_header)
        
        if replyto_matches and mailfrom_matches:
            replyto_email = replyto_matches[0]
            mailfrom_email = mailfrom_matches[0]
            
            if replyto_email == mailfrom_email:
                conclusion = "Reply Address and From Address are SAME."
            else:
                conclusion = "Reply Address and From Address are NOT same. This mail may be SPOOFED."
            
            data["Headers"]["Investigation"]["Spoof Check"] = {
                "Reply-To": replyto_email,
                "From": mailfrom_email,
                "Conclusion": conclusion
            }
        else:
            # Handle case where valid emails weren't found
            replyto_display = replyto_matches[0] if replyto_matches else "No valid email found"
            mailfrom_display = mailfrom_matches[0] if mailfrom_matches else "No valid email found"
            
            data["Headers"]["Investigation"]["Spoof Check"] = {
                "Reply-To": replyto_display,
                "From": mailfrom_display,
                "Conclusion": "Cannot determine spoof status - invalid or missing email addresses"
            }