"""
Link analyzer module for URL extraction and analysis.
"""

import re
from typing import Dict, Any, List
from email.message import EmailMessage
from urllib.parse import parse_qs, urlparse
from .base_analyzer import BaseAnalyzer


class LinkAnalyzer(BaseAnalyzer):
    """
    Analyzer for extracting and analyzing URLs from email content.
    """
    
    def __init__(self, investigation_mode: bool = False):
        super().__init__(investigation_mode)
        # Comprehensive HTML href regex
        self.link_regex = r'''(?i)href\s*=\s*(?:
            "([^"]*)"           |  # Double quotes
            '([^']*)'           |  # Single quotes  
            ([^\s>]+)              # No quotes (until space or >)
        )'''
        self.url_regex = r'https?://[^\s<>"{}|\\^`\[\]]+'
    
    def analyze(self, msg: EmailMessage, **kwargs) -> Dict[str, Any]:
        """
        Analyze email content for URLs and links.
        
        Args:
            msg: Email message object
            
        Returns:
            Dictionary containing link analysis results
        """
        data = self._create_data_structure("Links")
        
        # Extract links from email content
        links = self._extract_links(msg)
        
        # Populate data structure
        for index, link in enumerate(links, start=1):
            data["Links"]["Data"][str(index)] = link
        
        # Add investigation links if requested
        if self.investigation_mode:
            self._add_investigation_links_for_urls(data, links)
        
        self.results = data
        return data
    
    def _extract_links(self, msg: EmailMessage) -> List[str]:
        """
        Extract all URLs from email message.
        
        Args:
            msg: Email message object
            
        Returns:
            List of unique URLs found
        """
        links = set()
        
        # Get message content
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    content = part.get_content()
                    if isinstance(content, str):
                        links.update(self._extract_urls_from_content(content))
        else:
            content = msg.get_content()
            if isinstance(content, str):
                links.update(self._extract_urls_from_content(content))
        
        return list(links)
    
    def _extract_urls_from_content(self, content: str) -> List[str]:
        """
        Extract URLs from text content using multiple regex patterns.
        
        Args:
            content: Text content to analyze
            
        Returns:
            List of URLs found
        """
        urls = set()
        
        # Extract from href attributes
        href_matches = re.findall(self.link_regex, content, re.VERBOSE)
        for match in href_matches:
            # match is a tuple, get the non-empty group
            url = next((group for group in match if group), None)
            if url and self._is_valid_url(url):
                urls.add(url)
        
        # Extract standalone URLs
        url_matches = re.findall(self.url_regex, content)
        for url in url_matches:
            if self._is_valid_url(url):
                urls.add(url)
        
        return list(urls)
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate if a string is a proper URL.
        
        Args:
            url: URL string to validate
            
        Returns:
            True if valid URL, False otherwise
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
        except Exception:
            return False
    
    def _add_investigation_links_for_urls(self, data: Dict[str, Any], urls: List[str]) -> None:
        """
        Add investigation links for all extracted URLs.
        
        Args:
            data: Data structure to populate
            urls: List of URLs to investigate
        """
        for index, url in enumerate(urls, start=1):
            # Remove protocol for analysis
            analysis_url = url
            if "://" in analysis_url:
                analysis_url = analysis_url.split("://")[-1]
            
            data["Links"]["Investigation"][str(index)] = {
                "Virustotal": f"https://www.virustotal.com/gui/search/{analysis_url}",
                "Urlscan": f"https://urlscan.io/search/#{analysis_url}"
            }