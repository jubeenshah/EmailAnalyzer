"""
Digest analyzer module for file and content hashing.
"""

import hashlib
from typing import Dict, Any
from email.message import EmailMessage
from .base_analyzer import BaseAnalyzer


class DigestAnalyzer(BaseAnalyzer):
    """
    Analyzer for generating file and content hashes.
    """
    
    def analyze(self, msg: EmailMessage, filename: str = None, **kwargs) -> Dict[str, Any]:
        """
        Analyze email file and content to generate hash digests.
        
        Args:
            msg: Email message object
            filename: Path to the email file
            
        Returns:
            Dictionary containing hash analysis results
        """
        data = self._create_data_structure("Digests")
        
        # Generate file hashes if filename provided
        if filename:
            file_hashes = self._generate_file_hashes(filename)
            data["Digests"]["Data"].update(file_hashes)
        
        # Generate content hashes
        content_hashes = self._generate_content_hashes(msg)
        data["Digests"]["Data"].update(content_hashes)
        
        # Add investigation links if requested
        if self.investigation_mode:
            self._add_investigation_links_for_hashes(data)
        
        self.results = data
        return data
    
    def _generate_file_hashes(self, filename: str) -> Dict[str, str]:
        """
        Generate MD5, SHA1, and SHA256 hashes for the email file.
        
        Args:
            filename: Path to the email file
            
        Returns:
            Dictionary containing file hashes
        """
        try:
            with open(filename, 'rb') as f:
                file_content = f.read()
                
            return {
                "File MD5": hashlib.md5(file_content).hexdigest(),
                "File SHA1": hashlib.sha1(file_content).hexdigest(),
                "File SHA256": hashlib.sha256(file_content).hexdigest()
            }
        except (IOError, OSError) as e:
            return {
                "File MD5": f"Error reading file: {e}",
                "File SHA1": f"Error reading file: {e}",
                "File SHA256": f"Error reading file: {e}"
            }
    
    def _generate_content_hashes(self, msg: EmailMessage) -> Dict[str, str]:
        """
        Generate MD5, SHA1, and SHA256 hashes for the email content.
        
        Args:
            msg: Email message object
            
        Returns:
            Dictionary containing content hashes
        """
        try:
            content_str = str(msg)
            content_bytes = content_str.encode("utf-8")
            
            return {
                "Content MD5": hashlib.md5(content_bytes).hexdigest(),
                "Content SHA1": hashlib.sha1(content_bytes).hexdigest(),
                "Content SHA256": hashlib.sha256(content_bytes).hexdigest()
            }
        except Exception as e:
            return {
                "Content MD5": f"Error generating hash: {e}",
                "Content SHA1": f"Error generating hash: {e}",
                "Content SHA256": f"Error generating hash: {e}"
            }
    
    def _add_investigation_links_for_hashes(self, data: Dict[str, Any]) -> None:
        """
        Add VirusTotal investigation links for all generated hashes.
        
        Args:
            data: Data structure to populate
        """
        hash_types = ["File MD5", "File SHA1", "File SHA256", 
                     "Content MD5", "Content SHA1", "Content SHA256"]
        
        for hash_type in hash_types:
            hash_value = data["Digests"]["Data"].get(hash_type)
            if hash_value and not hash_value.startswith("Error"):
                data["Digests"]["Investigation"][hash_type] = {
                    "Virustotal": f"https://www.virustotal.com/gui/search/{hash_value}"
                }