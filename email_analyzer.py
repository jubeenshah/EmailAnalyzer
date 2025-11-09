"""
Main EmailAnalyzer class for orchestrating email security analysis.
"""

import json
from datetime import datetime
from email.parser import BytesParser
from email import policy
from io import BytesIO
from pathlib import Path
from typing import Dict, Any, Optional

from analyzers import (
    HeaderAnalyzer, LinkAnalyzer, DigestAnalyzer, AttachmentAnalyzer,
    TrackingAnalyzer, InfrastructureAnalyzer, AuthenticationAnalyzer
)
from output_formatter import OutputFormatter


class EmailAnalyzer:
    """
    Main class for comprehensive email security analysis.
    
    Coordinates multiple specialized analyzers to provide complete
    email analysis including headers, links, attachments, tracking,
    infrastructure, and authentication assessment.
    """
    
    def __init__(self, investigation_mode: bool = False):
        """
        Initialize EmailAnalyzer.
        
        Args:
            investigation_mode: Enable deep investigation analysis
        """
        self.investigation_mode = investigation_mode
        self.output_formatter = OutputFormatter()
        self.analyzers = {
            'headers': HeaderAnalyzer(investigation_mode),
            'links': LinkAnalyzer(investigation_mode),
            'digests': DigestAnalyzer(investigation_mode),
            'attachments': AttachmentAnalyzer(investigation_mode),
            'tracking': TrackingAnalyzer(investigation_mode),
            'infrastructure': InfrastructureAnalyzer(investigation_mode),
            'authentication': AuthenticationAnalyzer(investigation_mode)
        }
        self.output_formatter = OutputFormatter()
        self.results = {}
    
    def analyze_file(self, filename: str, 
                    analyze_headers: bool = True,
                    analyze_links: bool = True, 
                    analyze_digests: bool = True,
                    analyze_attachments: bool = True,
                    analyze_tracking: bool = True,
                    analyze_infrastructure: bool = True,
                    analyze_authentication: bool = True) -> Dict[str, Any]:
        """
        Analyze an email file with specified analysis modules.
        
        Args:
            filename: Path to email file
            analyze_headers: Enable header analysis
            analyze_links: Enable link analysis  
            analyze_digests: Enable digest analysis
            analyze_attachments: Enable attachment analysis
            analyze_tracking: Enable tracking pixel analysis
            analyze_infrastructure: Enable infrastructure analysis
            analyze_authentication: Enable authentication analysis
            
        Returns:
            Complete analysis results
        """
        # Parse email file
        msg = self._parse_email_file(filename)
        if not msg:
            return {"error": "Failed to parse email file"}
        
        # Initialize results structure
        self.results = {
            "Information": {
                "Project": {
                    "Name": "EmailAnalyzer",
                    "Url": "https://github.com/jubeenshah/EmailAnalyzer", 
                    "Version": "3.0"
                },
                "Scan": {
                    "Filename": filename,
                    "Generated": datetime.now().strftime("%B %d, %Y - %H:%M:%S")
                }
            },
            "Analysis": {}
        }
        
        # Run selected analyses
        if analyze_headers:
            result = self.analyzers['headers'].analyze(msg)
            self.results["Analysis"].update(result)
            
        if analyze_links:
            result = self.analyzers['links'].analyze(msg)
            self.results["Analysis"].update(result)
            
        if analyze_digests:
            result = self.analyzers['digests'].analyze(msg, filename=filename)
            self.results["Analysis"].update(result)
            
        if analyze_attachments:
            result = self.analyzers['attachments'].analyze(msg, filename=filename)
            self.results["Analysis"].update(result)
            
        if analyze_tracking:
            result = self.analyzers['tracking'].analyze(msg)
            self.results["Analysis"].update(result)
            
        if analyze_infrastructure:
            result = self.analyzers['infrastructure'].analyze(msg)
            self.results["Analysis"].update(result)
            
        if analyze_authentication:
            result = self.analyzers['authentication'].analyze(msg)
            self.results["Analysis"].update(result)
        
        return self.results
    
    def analyze_all(self, filenames) -> Dict[str, Dict[str, Any]]:
        """
        Perform analysis on multiple email files.
        
        Args:
            filenames: List of email file paths or single filename
            
        Returns:
            Dictionary mapping filenames to analysis results
        """
        if isinstance(filenames, (str, Path)):
            # Single file - convert to list
            filenames = [filenames]
        
        results = {}
        for filename in filenames:
            try:
                filename_str = str(filename)
                results[filename_str] = self.analyze_file(
                    filename_str,
                    analyze_headers=True,
                    analyze_links=True,
                    analyze_digests=True, 
                    analyze_attachments=True,
                    analyze_tracking=True,
                    analyze_infrastructure=True,
                    analyze_authentication=True
                )
            except Exception as e:
                results[str(filename)] = {
                    "EmailAnalyzer": "Error",
                    "Error": str(e),
                    "FileName": str(filename)
                }
        
        return results
    
    def print_results(self) -> None:
        """Print analysis results to terminal."""
        if self.results:
            self.formatter.print_terminal_output(self.results)
        else:
            print("No analysis results available. Run analysis first.")
    
    def save_results(self, output_filename: str) -> bool:
        """
        Save analysis results to file.
        
        Args:
            output_filename: Output file path (JSON or HTML)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.results:
            print("No analysis results to save. Run analysis first.")
            return False
            
        try:
            return self.formatter.save_results(self.results, output_filename)
        except Exception as e:
            print(f"Error saving results: {e}")
            return False
    
    def get_results(self) -> Dict[str, Any]:
        """Get raw analysis results."""
        return self.results
    
    def _parse_email_file(self, filename: str) -> Optional[Any]:
        """
        Parse email file using BytesParser.
        
        Args:
            filename: Path to email file
            
        Returns:
            Parsed email message or None if failed
        """
        try:
            with open(filename, "rb") as f:
                content = f.read()
                # Strip leading whitespace that can interfere with parsing
                content = content.lstrip()
                return BytesParser(policy=policy.default).parse(BytesIO(content))
        except Exception as e:
            print(f"Error parsing email file {filename}: {e}")
            return None