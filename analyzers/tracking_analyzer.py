"""
Tracking pixel analyzer for email messages.
"""

import re
from typing import Dict, Any, List
from analyzers.base_analyzer import BaseAnalyzer


class TrackingAnalyzer(BaseAnalyzer):
    """
    Analyzes tracking pixels and web beacons in email content.
    """
    
    # Known tracking pixel patterns
    TRACKING_PATTERNS = {
        'mailchimp': {
            'pattern': r'list-manage\.com.*?open',
            'indicators': ['list-manage.com', '/open']
        },
        'constant_contact': {
            'pattern': r'constantcontact\.com.*?(open|track)',
            'indicators': ['constantcontact.com', '/open', '/track']
        },
        'sendgrid': {
            'pattern': r'sendgrid\.net.*?(open|track)',
            'indicators': ['sendgrid.net', '/open', '/track']
        },
        'mailgun': {
            'pattern': r'mailgun\.org.*?(open|track)',
            'indicators': ['mailgun.org', '/open', '/track']
        },
        'hubspot': {
            'pattern': r'hubspot\.com.*?(open|track)',
            'indicators': ['hubspot.com', '/open', '/track']
        },
        'campaign_monitor': {
            'pattern': r'createsend\.com.*?(open|track)',
            'indicators': ['createsend.com', '/open', '/track']
        },
        'aweber': {
            'pattern': r'aweber\.com.*?(open|track)',
            'indicators': ['aweber.com', '/open', '/track']
        },
        'getresponse': {
            'pattern': r'getresponse\.com.*?(open|track)',
            'indicators': ['getresponse.com', '/open', '/track']
        },
        'amazon_ses': {
            'pattern': r'amazonaws\.com.*?(open|track)',
            'indicators': ['amazonaws.com', '/open', '/track']
        }
    }
    
    def analyze(self, message, filename: str = None) -> Dict[str, Any]:
        """
        Analyze tracking pixels in the email message.
        
        Args:
            message: Email message object
            filename: Optional filename for context
            
        Returns:
            Dictionary containing tracking analysis results
        """
        data = self._create_data_structure("TrackingPixels")
        tracking_pixels = []
        
        # Extract HTML content
        html_content = self._extract_html_content(message)
        
        if html_content:
            # Find tracking pixels
            tracking_pixels.extend(self._find_tracking_pixels(html_content))
            tracking_pixels.extend(self._find_suspicious_images(html_content))
            
        # Structure the results
        data['TrackingPixels']['Data'] = {
            'count': len(tracking_pixels),
            'items': tracking_pixels
        }
        
        # Create investigation links for each tracking pixel
        for i, pixel in enumerate(tracking_pixels):
            self._add_investigation_links(
                data,
                f'TrackingPixel_{i+1}',
                pixel['url']
            )
        
        return data
    
    def _extract_html_content(self, message) -> str:
        """
        Extract HTML content from email message.
        
        Args:
            message: Email message object
            
        Returns:
            HTML content as string
        """
        html_content = ""
        
        try:
            if hasattr(message, 'walk'):
                for part in message.walk():
                    if part.get_content_type() == "text/html":
                        charset = part.get_content_charset() or 'utf-8'
                        payload = part.get_payload(decode=True)
                        if payload:
                            try:
                                html_content += payload.decode(charset, errors='ignore')
                            except Exception:
                                html_content += payload.decode('utf-8', errors='ignore')
            else:
                # Simple message object
                if message.get_content_type() == "text/html":
                    html_content = str(message.get_payload())
                    
        except Exception as e:
            print(f"Error extracting HTML content: {e}")
        
        return html_content
    
    def _find_tracking_pixels(self, html_content: str) -> List[Dict[str, Any]]:
        """
        Find known tracking service pixels.
        
        Args:
            html_content: HTML content to analyze
            
        Returns:
            List of tracking pixel dictionaries
        """
        pixels = []
        
        # Find all img tags
        img_tags = re.findall(r'<img[^>]*>', html_content, re.IGNORECASE)
        
        for img_tag in img_tags:
            # Extract src attribute
            src_match = re.search(r'src=["\']([^"\']*)["\']', img_tag, re.IGNORECASE)
            if src_match:
                src_url = src_match.group(1)
                
                # Check against known tracking patterns
                for provider, pattern_info in self.TRACKING_PATTERNS.items():
                    if re.search(pattern_info['pattern'], src_url, re.IGNORECASE):
                        pixels.append({
                            'url': src_url,
                            'provider': provider,
                            'reason': f'Matches {provider} tracking pattern',
                            'tag': img_tag
                        })
                        break
        
        return pixels
    
    def _find_suspicious_images(self, html_content: str) -> List[Dict[str, Any]]:
        """
        Find suspicious images that could be tracking pixels.
        
        Args:
            html_content: HTML content to analyze
            
        Returns:
            List of suspicious image dictionaries
        """
        pixels = []
        
        # Find all img tags with src
        img_pattern = r'<img[^>]*src=["\']([^"\']*)["\'][^>]*>'
        img_matches = re.findall(img_pattern, html_content, re.IGNORECASE)
        
        for src_url in img_matches:
            reasons = []
            
            # Check for 1x1 pixel indicators
            if re.search(r'[?&]width=1|[?&]height=1|[?&]w=1|[?&]h=1', src_url, re.IGNORECASE):
                reasons.append('1x1 pixel dimensions in URL')
            
            # Check for tracking-like parameters
            tracking_params = ['track', 'open', 'pixel', 'beacon', 'analytics', 'utm_', 'campaign']
            for param in tracking_params:
                if param in src_url.lower():
                    reasons.append(f'Contains tracking parameter: {param}')
            
            # Check for suspicious file extensions or lack thereof
            if not re.search(r'\.(jpg|jpeg|png|gif|bmp|svg)$', src_url, re.IGNORECASE):
                if '.' not in src_url.split('/')[-1] or len(src_url.split('/')[-1]) > 50:
                    reasons.append('Suspicious or missing file extension')
            
            # Check for encoded parameters
            if len(src_url) > 100 and ('=' in src_url or '%' in src_url):
                reasons.append('Long URL with encoded parameters')
            
            # Check for randomized IDs
            if re.search(r'[a-f0-9]{16,}|[A-Z0-9]{10,}', src_url):
                reasons.append('Contains long random identifier')
            
            # If we found reasons, it's likely a tracking pixel
            if reasons:
                pixels.append({
                    'url': src_url,
                    'provider': 'unknown',
                    'reason': '; '.join(reasons),
                    'tag': f'<img src="{src_url}">'
                })
        
        return pixels
    
    def _is_likely_tracking_pixel(self, img_tag: str, src_url: str) -> bool:
        """
        Determine if an image is likely a tracking pixel based on attributes.
        
        Args:
            img_tag: Full img tag
            src_url: Source URL
            
        Returns:
            True if likely a tracking pixel
        """
        # Check for 1x1 dimensions
        if re.search(r'width=["\']?1["\']?|height=["\']?1["\']?', img_tag, re.IGNORECASE):
            return True
        
        # Check for hidden styling
        if re.search(r'display:\s*none|visibility:\s*hidden|opacity:\s*0', img_tag, re.IGNORECASE):
            return True
        
        # Check for tracking-like URLs
        tracking_indicators = [
            'track', 'pixel', 'beacon', 'open', 'analytics',
            'utm_', 'campaign', 'email_id', 'user_id'
        ]
        
        for indicator in tracking_indicators:
            if indicator in src_url.lower():
                return True
        
        return False