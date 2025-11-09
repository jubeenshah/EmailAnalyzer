"""
Attachment analyzer for email messages.
"""

import mimetypes
import re
import hashlib
from pathlib import Path
from typing import Dict, Any, List
from analyzers.base_analyzer import BaseAnalyzer


class AttachmentAnalyzer(BaseAnalyzer):
    """
    Analyzes email attachments and creates investigation links.
    """
    
    def analyze(self, message, filename: str = None) -> Dict[str, Any]:
        """
        Analyze attachments in the email message.
        
        Args:
            message: Email message object
            filename: Optional filename for context
            
        Returns:
            Dictionary containing attachment analysis results
        """
        data = self._create_data_structure("Attachments")
        attachments = self._extract_attachments(message)
        
        if attachments:
            for i, attachment in enumerate(attachments):
                attachment_name = attachment.get('filename', f'attachment_{i+1}')
                data['Attachments']['Data'][f'Attachment_{i+1}'] = {
                    'filename': attachment_name,
                    'mime_type': attachment.get('mime_type', 'unknown'),
                    'size': attachment.get('size', 'unknown'),
                    'content_disposition': attachment.get('disposition', 'unknown')
                }
                
                # Create investigation links for each attachment
                self._add_investigation_links(
                    data, 
                    f'Attachment_{i+1}', 
                    attachment_name
                )
                
                # Add additional hash-based investigation for binary content
                if attachment.get('content'):
                    content_hash = self._calculate_content_hash(attachment['content'])
                    if content_hash:
                        data['Attachments']['Investigation'][f'Attachment_{i+1}_Hash'] = {
                            'VirusTotal': f'https://www.virustotal.com/gui/search/{content_hash}',
                            'SHA256': content_hash
                        }
        else:
            data['Attachments']['Data']['status'] = 'No attachments found'
        
        return data
    
    def _extract_attachments(self, message) -> List[Dict[str, Any]]:
        """
        Extract attachment information from email message.
        
        Args:
            message: Email message object
            
        Returns:
            List of attachment dictionaries
        """
        attachments = []
        
        # Walk through message parts
        if hasattr(message, 'walk'):
            for part in message.walk():
                # Skip multipart containers
                if part.get_content_maintype() == 'multipart':
                    continue
                
                # Check for attachment disposition
                disposition = part.get('Content-Disposition', '')
                filename = self._extract_filename(part)
                
                # Consider it an attachment if it has a filename or attachment disposition
                if filename or 'attachment' in disposition.lower():
                    attachment_info = {
                        'filename': filename or 'unnamed_attachment',
                        'mime_type': part.get_content_type(),
                        'disposition': disposition,
                        'size': self._calculate_size(part),
                        'content': self._get_attachment_content(part)
                    }
                    attachments.append(attachment_info)
        
        return attachments
    
    def _extract_filename(self, part) -> str:
        """
        Extract filename from email part.
        
        Args:
            part: Email message part
            
        Returns:
            Extracted filename or None
        """
        filename = None
        
        # Try Content-Disposition header first
        disposition = part.get('Content-Disposition', '')
        if disposition:
            # Look for filename in disposition
            filename_match = re.search(r'filename[*]?=([^;]+)', disposition, re.IGNORECASE)
            if filename_match:
                filename = filename_match.group(1).strip('"\'')
        
        # Try Content-Type header if no filename found
        if not filename:
            content_type = part.get('Content-Type', '')
            if content_type:
                name_match = re.search(r'name[*]?=([^;]+)', content_type, re.IGNORECASE)
                if name_match:
                    filename = name_match.group(1).strip('"\'')
        
        # Clean up filename encoding if present
        if filename:
            filename = self._decode_filename(filename)
        
        return filename
    
    def _decode_filename(self, filename: str) -> str:
        """
        Decode encoded filename.
        
        Args:
            filename: Potentially encoded filename
            
        Returns:
            Decoded filename
        """
        try:
            # Handle RFC 2231 encoding
            if filename.startswith(('utf-8\'\'', 'iso-8859-1\'\'')):
                import urllib.parse
                if filename.startswith('utf-8\'\''):
                    filename = urllib.parse.unquote(filename[7:])
                elif filename.startswith('iso-8859-1\'\''):
                    filename = urllib.parse.unquote(filename[12:])
            
            # Remove any remaining quotes
            filename = filename.strip('"\'')
            
        except Exception as e:
            # If decoding fails, return as-is - this is expected for some encodings
            print(f"Warning: Failed to decode filename '{filename}': {e}")
        
        return filename
    
    def _calculate_size(self, part) -> str:
        """
        Calculate attachment size.
        
        Args:
            part: Email message part
            
        Returns:
            Size as string with units
        """
        try:
            content = part.get_payload(decode=True)
            if content:
                size = len(content)
                return self._format_size(size)
        except Exception as e:
            # Unable to decode payload - this is expected for some attachment types
            print(f"Warning: Failed to calculate attachment size: {e}")
        
        return 'unknown'
    
    def _format_size(self, size_bytes: int) -> str:
        """
        Format size in human-readable format.
        
        Args:
            size_bytes: Size in bytes
            
        Returns:
            Formatted size string
        """
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 ** 2:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 ** 3:
            return f"{size_bytes / (1024 ** 2):.1f} MB"
        else:
            return f"{size_bytes / (1024 ** 3):.1f} GB"
    
    def _get_attachment_content(self, part) -> bytes:
        """
        Get attachment content for hash calculation.
        
        Args:
            part: Email message part
            
        Returns:
            Attachment content as bytes
        """
        try:
            return part.get_payload(decode=True)
        except Exception:
            return b''
    
    def _calculate_content_hash(self, content: bytes) -> str:
        """
        Calculate SHA256 hash of attachment content.
        
        Args:
            content: Attachment content
            
        Returns:
            SHA256 hash string
        """
        try:
            if content:
                return hashlib.sha256(content).hexdigest()
        except Exception as e:
            # Unable to hash content - this is expected for empty or invalid content
            print(f"Warning: Failed to calculate SHA256 hash: {e}")
        
        return None