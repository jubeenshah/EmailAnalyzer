"""
Output formatter for EmailAnalyzer results.
"""

import json
import os
from typing import Dict, Any
from clean_banners import (
    print_introduction, print_section_header, print_analysis_complete
)
from html_generator import generate_table_from_json, generate_batch_html_report


class OutputFormatter:
    """
    Handles formatting and output of analysis results.
    """
    
    def __init__(self):
        self.terminal_column_size = self._get_terminal_width()
    
    def print_terminal_output(self, results: Dict[str, Any]) -> None:
        """
        Print analysis results to terminal with clean formatting.
        
        Args:
            results: Analysis results dictionary
        """
        print_introduction()
        
        analysis_data = results.get("Analysis", {})
        
        # Print each analysis section
        if analysis_data.get("Headers"):
            self._print_headers_section(analysis_data["Headers"])
            
        if analysis_data.get("Links"):
            self._print_links_section(analysis_data["Links"])
            
        if analysis_data.get("Digests"):
            self._print_digests_section(analysis_data["Digests"])
            
        if analysis_data.get("Attachments"):
            self._print_attachments_section(analysis_data["Attachments"])
            
        if analysis_data.get("TrackingPixels"):
            self._print_tracking_section(analysis_data["TrackingPixels"])
            
        if analysis_data.get("Infrastructure"):
            self._print_infrastructure_section(analysis_data["Infrastructure"])
            
        if analysis_data.get("Auth"):
            self._print_authentication_section(analysis_data["Auth"])
        
        print_analysis_complete()
    
    def save_results(self, results: Dict[str, Any], filename: str) -> bool:
        """
        Save results to file in JSON or HTML format.
        
        Args:
            results: Analysis results
            filename: Output filename
            
        Returns:
            True if successful
        """
        file_extension = filename.split('.')[-1].lower()
        
        try:
            if file_extension == "json":
                with open(filename, 'w', encoding="utf-8") as f:
                    json.dump(results, f, indent=4)
                    
            elif file_extension == "html":
                with open(filename, 'w', encoding="utf-8") as f:
                    # Debug: Print the results structure
                    print(f"Debug - Results type: {type(results)}")
                    print(f"Debug - Results keys: {list(results.keys()) if isinstance(results, dict) else 'Not a dict'}")
                    
                    # Check if this is a batch result
                    if "TotalFiles" in results and "Files" in results:
                        # Use batch HTML generator
                        print("Debug - Using batch HTML generator")
                        html_content = generate_batch_html_report(results)
                    else:
                        # Use single-file HTML generator
                        print("Debug - Using single file HTML generator")
                        html_content = generate_table_from_json(results)
                    f.write(html_content)
                    
            else:
                print(f"Unsupported file format: {file_extension}")
                return False
                
            print(f"Results saved to {filename}")
            return True
            
        except Exception as e:
            print(f"Error saving file: {e}")
            return False
    
    def _print_headers_section(self, headers_data: Dict[str, Any]) -> None:
        """Print headers analysis section."""
        print_section_header("Headers", "📧")
        
        # Print basic header data
        for key, value in headers_data["Data"].items():
            if isinstance(value, list):
                print(f"[{key}]")
                for item in value:
                    print(f"  {item}")
            else:
                print(f"[{key}]")
                print(f"{value}")
            self._print_separator()
        
        # Print investigation results
        if headers_data.get("Investigation"):
            print_section_header("Investigation", "🔍")
            for key, data in headers_data["Investigation"].items():
                self._print_investigation_item(key, data)
    
    def _print_links_section(self, links_data: Dict[str, Any]) -> None:
        """Print links analysis section."""
        print_section_header("Links", "🔗")
        
        for key, url in links_data["Data"].items():
            print(f"[{key}] -> {url}")
        
        if links_data.get("Investigation"):
            print_section_header("Investigation", "🔍")
            for key, data in links_data["Investigation"].items():
                self._print_investigation_item(key, data)
    
    def _print_digests_section(self, digests_data: Dict[str, Any]) -> None:
        """Print digests analysis section."""
        print_section_header("Digests", "🔐")
        
        for key, value in digests_data["Data"].items():
            print(f"[{key}]")
            print(f"{value}")
            self._print_separator()
        
        if digests_data.get("Investigation"):
            print_section_header("Investigation", "🔍")
            for key, data in digests_data["Investigation"].items():
                self._print_investigation_item(key, data)
    
    def _print_attachments_section(self, attachments_data: Dict[str, Any]) -> None:
        """Print attachments analysis section.""" 
        print_section_header("Attachments", "📎")
        
        for key, filename in attachments_data["Data"].items():
            print(f"[{key}] -> {filename}")
            self._print_separator()
        
        if attachments_data.get("Investigation"):
            print_section_header("Investigation", "🔍")
            for key, data in attachments_data["Investigation"].items():
                self._print_investigation_item(key, data)
    
    def _print_tracking_section(self, tracking_data: Dict[str, Any]) -> None:
        """Print tracking pixels analysis section."""
        print_section_header("Tracking Pixels", "👁")
        
        pixel_count = tracking_data["Data"]["count"]
        print(f"Tracking Pixels Detected: {pixel_count}")
        
        for i, pixel in enumerate(tracking_data["Data"]["items"], 1):
            print(f"[{i}] Provider: {pixel['provider']}")
            print(f"    URL: {pixel['url']}")
            print(f"    Reason: {pixel['reason']}")
            self._print_separator()
    
    def _print_infrastructure_section(self, infra_data: Dict[str, Any]) -> None:
        """Print infrastructure analysis section."""
        print_section_header("Infrastructure", "🏗")
        
        data = infra_data["Data"]
        print(f"Return Path: {data['return_path']}")
        print(f"Message-ID Domain: {data['message_id_domain']}")
        print(f"Classification: {data['classification']}")
        self._print_separator()
    
    def _print_authentication_section(self, auth_data: Dict[str, Any]) -> None:
        """Print authentication analysis section."""
        print_section_header("Authentication", "🛡")
        
        data = auth_data["Data"]
        print(f"SPF: {data['SPF']}")
        print(f"DKIM: {data['DKIM']}")
        print(f"DMARC: {data['DMARC']}")
        print(f"Conclusion: {data['Conclusion']}")
        self._print_separator()
    
    def _print_investigation_item(self, key: str, data: Any) -> None:
        """Print individual investigation item."""
        print(f"[{key}]")
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and v.startswith("http"):
                    print(f"{k}: {v}")
                else:
                    print(f"{k}: {v}")
        else:
            print(f"{data}")
        self._print_separator()
    
    def _print_separator(self) -> None:
        """Print section separator."""
        print("_" * min(self.terminal_column_size, 60))
    
    def _get_terminal_width(self) -> int:
        """Get terminal width for formatting."""
        try:
            return os.get_terminal_size().columns
        except Exception:
            return 80  # Default width