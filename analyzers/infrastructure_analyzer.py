"""
Infrastructure analyzer for email message routing and classification.
"""

import re
from typing import Dict, Any
from analyzers.base_analyzer import BaseAnalyzer


class InfrastructureAnalyzer(BaseAnalyzer):
    """
    Analyzes email infrastructure and routing information.
    """
    
    def analyze(self, message, filename: str = None) -> Dict[str, Any]:
        """
        Analyze infrastructure characteristics of the email.
        
        Args:
            message: Email message object
            filename: Optional filename for context
            
        Returns:
            Dictionary containing infrastructure analysis results
        """
        data = self._create_data_structure("Infrastructure")
        
        # Extract key infrastructure elements
        return_path = self._extract_return_path(message)
        message_id_domain = self._extract_message_id_domain(message)
        
        # Classify the email type
        classification = self._classify_email(message, return_path, message_id_domain)
        
        data['Infrastructure']['Data'] = {
            'return_path': return_path or 'Not found',
            'message_id_domain': message_id_domain or 'Not found',
            'classification': classification,
            'routing_analysis': self._analyze_routing(message)
        }
        
        # Add investigation links for domains
        if return_path and '@' in return_path:
            domain = return_path.split('@')[1]
            self._add_investigation_links(data, 'ReturnPathDomain', domain)
            
        if message_id_domain:
            self._add_investigation_links(data, 'MessageIDDomain', message_id_domain)
        
        return data
    
    def _extract_return_path(self, message) -> str:
        """
        Extract return path from email headers.
        
        Args:
            message: Email message object
            
        Returns:
            Return path or None
        """
        # Try Return-Path header first
        return_path = message.get('Return-Path')
        if return_path:
            # Clean up the return path (remove angle brackets)
            return_path = re.sub(r'[<>]', '', return_path).strip()
            return return_path
        
        # Fall back to From header
        from_header = message.get('From')
        if from_header:
            # Extract email address from From header
            email_match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
            if email_match:
                return email_match.group(0)
        
        return None
    
    def _extract_message_id_domain(self, message) -> str:
        """
        Extract domain from Message-ID header.
        
        Args:
            message: Email message object
            
        Returns:
            Domain from Message-ID or None
        """
        message_id = message.get('Message-ID')
        if message_id:
            # Message-ID format: <unique@domain.com>
            domain_match = re.search(r'@([\w\.-]+)', message_id)
            if domain_match:
                return domain_match.group(1)
        
        return None
    
    def _classify_email(self, message, return_path: str, message_id_domain: str) -> str:
        """
        Classify the email based on infrastructure characteristics.
        
        Args:
            message: Email message object
            return_path: Return path address
            message_id_domain: Domain from Message-ID
            
        Returns:
            Classification string
        """
        classifications = []
        
        # Check for bulk email indicators
        if self._is_bulk_email(message):
            classifications.append("Bulk/Marketing")
        
        # Check for automated email indicators
        if self._is_automated_email(message):
            classifications.append("Automated")
        
        # Check for transactional email indicators
        if self._is_transactional_email(message):
            classifications.append("Transactional")
        
        # Check for suspicious characteristics
        if self._has_suspicious_infrastructure(message, return_path, message_id_domain):
            classifications.append("Suspicious")
        
        # Check for legitimate business email
        if self._is_legitimate_business_email(message):
            classifications.append("Business")
        
        return " / ".join(classifications) if classifications else "Unknown"
    
    def _is_bulk_email(self, message) -> bool:
        """Check if email appears to be bulk/marketing email."""
        bulk_indicators = [
            'List-Unsubscribe', 'List-ID', 'Precedence',
            'X-Campaign', 'X-Mailer', 'X-Bulk'
        ]
        
        for header in bulk_indicators:
            if message.get(header):
                return True
        
        # Check for bulk email patterns in headers
        mailer = message.get('X-Mailer', '').lower()
        if any(term in mailer for term in ['mailchimp', 'constant contact', 'campaign monitor']):
            return True
        
        return False
    
    def _is_automated_email(self, message) -> bool:
        """Check if email appears to be automated."""
        auto_indicators = [
            'Auto-Submitted', 'X-Auto-Response-Suppress'
        ]
        
        for header in auto_indicators:
            if message.get(header):
                return True
        
        # Check subject for automated patterns
        subject = message.get('Subject', '').lower()
        auto_terms = ['automatic', 'auto-reply', 'out of office', 'delivery failure']
        if any(term in subject for term in auto_terms):
            return True
        
        return False
    
    def _is_transactional_email(self, message) -> bool:
        """Check if email appears to be transactional."""
        subject = message.get('Subject', '').lower()
        trans_terms = [
            'receipt', 'invoice', 'order', 'confirmation',
            'password', 'account', 'verification', 'statement'
        ]
        
        return any(term in subject for term in trans_terms)
    
    def _has_suspicious_infrastructure(self, message, return_path: str, message_id_domain: str) -> bool:
        """Check for suspicious infrastructure characteristics."""
        suspicious_indicators = []
        
        # Check for domain mismatches
        from_header = message.get('From', '')
        from_domain = None
        if '@' in from_header:
            from_match = re.search(r'@([\w\.-]+)', from_header)
            if from_match:
                from_domain = from_match.group(1)
        
        return_domain = None
        if return_path and '@' in return_path:
            return_domain = return_path.split('@')[1]
        
        # Flag if domains don't match and aren't related
        if (from_domain and return_domain and 
            from_domain != return_domain and 
            not self._domains_related(from_domain, return_domain)):
            suspicious_indicators.append("Domain mismatch")
        
        # Check for missing critical headers
        critical_headers = ['Date', 'From', 'Message-ID']
        missing_headers = [h for h in critical_headers if not message.get(h)]
        if missing_headers:
            suspicious_indicators.append(f"Missing headers: {', '.join(missing_headers)}")
        
        # Check for suspicious routing
        received_headers = message.get_all('Received') or []
        if len(received_headers) > 10:
            suspicious_indicators.append("Excessive hops")
        
        return len(suspicious_indicators) > 0
    
    def _is_legitimate_business_email(self, message) -> bool:
        """Check if email appears to be legitimate business communication."""
        # Look for business-like characteristics
        from_header = message.get('From', '')
        
        # Check for corporate domains
        corporate_tlds = ['.com', '.org', '.edu', '.gov', '.mil']
        if any(tld in from_header for tld in corporate_tlds):
            # Check for proper formatting
            if re.search(r'[\w\s]+ <[\w\.-]+@[\w\.-]+>', from_header):
                return True
        
        return False
    
    def _domains_related(self, domain1: str, domain2: str) -> bool:
        """Check if two domains are related (subdomains, etc.)."""
        if not domain1 or not domain2:
            return False
        
        # Simple check for subdomain relationship
        return (domain1 in domain2 or domain2 in domain1 or
                domain1.split('.')[-2:] == domain2.split('.')[-2:])
    
    def _analyze_routing(self, message) -> Dict[str, Any]:
        """
        Analyze email routing path.
        
        Args:
            message: Email message object
            
        Returns:
            Routing analysis dictionary
        """
        received_headers = message.get_all('Received') or []
        
        routing_info = {
            'hop_count': len(received_headers),
            'first_hop': None,
            'last_hop': None,
            'suspicious_hops': []
        }
        
        if received_headers:
            # First received header is usually the last hop
            routing_info['first_hop'] = received_headers[0][:100] + "..." if len(received_headers[0]) > 100 else received_headers[0]
            
            # Last received header is usually the first hop
            routing_info['last_hop'] = received_headers[-1][:100] + "..." if len(received_headers[-1]) > 100 else received_headers[-1]
            
            # Look for suspicious patterns in routing
            for hop in received_headers:
                if self._is_suspicious_hop(hop):
                    routing_info['suspicious_hops'].append(hop[:100] + "...")
        
        return routing_info
    
    def _is_suspicious_hop(self, received_header: str) -> bool:
        """Check if a received header looks suspicious."""
        suspicious_patterns = [
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # Bare IP addresses
            r'unknown',  # Unknown hostnames
            r'localhost',  # Localhost references
            r'[a-f0-9]{8,}',  # Long hex strings (could be obfuscation)
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, received_header, re.IGNORECASE):
                return True
        
        return False