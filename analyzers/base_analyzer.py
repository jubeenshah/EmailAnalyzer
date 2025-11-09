"""
Base analyzer class for email analysis modules.
"""

import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Union
from email.message import EmailMessage


class BaseAnalyzer(ABC):
    """
    Abstract base class for all email analyzers.
    Provides common functionality and interface.
    """
    
    def __init__(self, investigation_mode: bool = False):
        """
        Initialize analyzer.
        
        Args:
            investigation_mode: Whether to perform deep investigation
        """
        self.investigation_mode = investigation_mode
        self.results = {}
    
    @abstractmethod
    def analyze(self, msg: EmailMessage, **kwargs) -> Dict[str, Any]:
        """
        Analyze email message and return results.
        
        Args:
            msg: Email message object
            **kwargs: Additional arguments
            
        Returns:
            Dictionary containing analysis results
        """
        pass
    
    def _create_data_structure(self, analyzer_name: str = "Analysis") -> Dict[str, Any]:
        """
        Create standard data structure for analysis results.
        
        Args:
            analyzer_name: Name of the analyzer (e.g., 'Headers', 'Links')
            
        Returns:
            Standard data structure dictionary
        """
        return {
            analyzer_name: {
                'Data': {},
                'Investigation': {}
            }
        }
    
    def _add_investigation_links(self, base_data: Dict[str, Any], 
                               index: Union[str, int], item: str) -> None:
        """
        Add investigation links for VirusTotal and other services.
        
        Args:
            base_data: Data structure to add investigation to
            index: Index or key for the investigation item
            item: Item to investigate (URL, IP, hash, etc.)
        """
        if not self.investigation_mode:
            return
            
        # Remove protocol for analysis
        analysis_item = item
        if "://" in analysis_item:
            analysis_item = analysis_item.split("://")[-1]
        
        # Find the first section in the data structure to add investigation to
        for section_name, section_data in base_data.items():
            if isinstance(section_data, dict) and 'Investigation' in section_data:
                section_data["Investigation"][index] = {
                    "Virustotal": f"https://www.virustotal.com/gui/search/{analysis_item}",
                    "Urlscan": f"https://urlscan.io/search/#{analysis_item}"
                }
                break
    
    def get_results(self) -> Dict[str, Any]:
        """Get analysis results."""
        return self.results
    
    def clear_results(self) -> None:
        """Clear stored results."""
        self.results = {}