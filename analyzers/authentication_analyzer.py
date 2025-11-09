"""
Authentication analyzer for email security headers (SPF, DKIM, DMARC, ARC).
"""

import re
from typing import Dict, Any, List, Tuple
from analyzers.base_analyzer import BaseAnalyzer


class AuthenticationAnalyzer(BaseAnalyzer):
    """
    Analyzes email authentication headers and provides security assessment.
    """
    
    def analyze(self, message, filename: str = None) -> Dict[str, Any]:
        """
        Analyze authentication headers in the email message.
        
        Args:
            message: Email message object
            filename: Optional filename for context
            
        Returns:
            Dictionary containing authentication analysis results
        """
        data = self._create_data_structure("Auth")
        
        # Extract and analyze authentication headers
        auth_results = self._parse_authentication_results(message)
        spf_result = self._analyze_spf(message, auth_results)
        dkim_result = self._analyze_dkim(message, auth_results)
        dmarc_result = self._analyze_dmarc(message, auth_results)
        arc_result = self._analyze_arc(message)
        
        # Calculate overall authentication conclusion
        conclusion = self._calculate_conclusion(spf_result, dkim_result, dmarc_result, arc_result)
        
        data['Auth']['Data'] = {
            'SPF': spf_result,
            'DKIM': dkim_result,
            'DMARC': dmarc_result,
            'ARC': arc_result,
            'Conclusion': conclusion,
            'Details': {
                'confidence_score': self._calculate_confidence_score(spf_result, dkim_result, dmarc_result),
                'security_recommendations': self._generate_security_recommendations(spf_result, dkim_result, dmarc_result),
                'raw_headers': self._extract_raw_auth_headers(message)
            }
        }
        
        return data
    
    def _parse_authentication_results(self, message) -> Dict[str, List[str]]:
        """
        Parse Authentication-Results headers.
        
        Args:
            message: Email message object
            
        Returns:
            Dictionary of parsed authentication results
        """
        auth_headers = message.get_all('Authentication-Results') or []
        results = {'spf': [], 'dkim': [], 'dmarc': [], 'arc': []}
        
        for header in auth_headers:
            # Parse SPF results
            spf_matches = re.findall(r'spf=([^;]+)', header, re.IGNORECASE)
            results['spf'].extend(spf_matches)
            
            # Parse DKIM results  
            dkim_matches = re.findall(r'dkim=([^;]+)', header, re.IGNORECASE)
            results['dkim'].extend(dkim_matches)
            
            # Parse DMARC results
            dmarc_matches = re.findall(r'dmarc=([^;]+)', header, re.IGNORECASE)
            results['dmarc'].extend(dmarc_matches)
            
            # Parse ARC results
            arc_matches = re.findall(r'arc=([^;]+)', header, re.IGNORECASE)
            results['arc'].extend(arc_matches)
        
        return results
    
    def _analyze_spf(self, message, auth_results: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Analyze SPF authentication.
        
        Args:
            message: Email message object
            auth_results: Parsed authentication results
            
        Returns:
            SPF analysis dictionary
        """
        spf_analysis = {
            'status': 'unknown',
            'details': [],
            'raw_header': None
        }
        
        # Check Received-SPF header
        received_spf = message.get('Received-SPF')
        if received_spf:
            spf_analysis['raw_header'] = received_spf
            spf_analysis['details'].append(f"Received-SPF: {received_spf}")
            
            # Parse the result
            if 'pass' in received_spf.lower():
                spf_analysis['status'] = 'pass'
            elif 'fail' in received_spf.lower():
                spf_analysis['status'] = 'fail'
            elif 'softfail' in received_spf.lower():
                spf_analysis['status'] = 'softfail'
            elif 'neutral' in received_spf.lower():
                spf_analysis['status'] = 'neutral'
            elif 'none' in received_spf.lower():
                spf_analysis['status'] = 'none'
        
        # Check Authentication-Results for SPF
        if auth_results['spf']:
            for spf_result in auth_results['spf']:
                spf_analysis['details'].append(f"Auth-Results SPF: {spf_result.strip()}")
                result_status = spf_result.strip().split()[0].lower()
                if result_status in ['pass', 'fail', 'softfail', 'neutral', 'none']:
                    spf_analysis['status'] = result_status
        
        return spf_analysis
    
    def _analyze_dkim(self, message, auth_results: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Analyze DKIM authentication.
        
        Args:
            message: Email message object
            auth_results: Parsed authentication results
            
        Returns:
            DKIM analysis dictionary
        """
        dkim_analysis = {
            'status': 'unknown',
            'details': [],
            'signatures': []
        }
        
        # Check DKIM-Signature headers
        dkim_signatures = message.get_all('DKIM-Signature') or []
        for i, signature in enumerate(dkim_signatures):
            dkim_analysis['signatures'].append({
                'index': i + 1,
                'header': signature[:200] + "..." if len(signature) > 200 else signature,
                'domain': self._extract_dkim_domain(signature),
                'selector': self._extract_dkim_selector(signature)
            })
        
        # Check Authentication-Results for DKIM
        if auth_results['dkim']:
            for dkim_result in auth_results['dkim']:
                dkim_analysis['details'].append(f"Auth-Results DKIM: {dkim_result.strip()}")
                result_status = dkim_result.strip().split()[0].lower()
                if result_status in ['pass', 'fail', 'neutral', 'none']:
                    dkim_analysis['status'] = result_status
        
        # If no auth results but we have signatures, mark as present
        if dkim_signatures and dkim_analysis['status'] == 'unknown':
            dkim_analysis['status'] = 'present'
            dkim_analysis['details'].append("DKIM signatures present but validation status unknown")
        
        return dkim_analysis
    
    def _analyze_dmarc(self, message, auth_results: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Analyze DMARC authentication.
        
        Args:
            message: Email message object
            auth_results: Parsed authentication results
            
        Returns:
            DMARC analysis dictionary
        """
        dmarc_analysis = {
            'status': 'unknown',
            'details': [],
            'policy': None
        }
        
        # Check Authentication-Results for DMARC
        if auth_results['dmarc']:
            for dmarc_result in auth_results['dmarc']:
                dmarc_analysis['details'].append(f"Auth-Results DMARC: {dmarc_result.strip()}")
                
                # Extract status
                result_status = dmarc_result.strip().split()[0].lower()
                if result_status in ['pass', 'fail', 'none']:
                    dmarc_analysis['status'] = result_status
                
                # Extract policy if present
                policy_match = re.search(r'policy\.([^;=]+)', dmarc_result, re.IGNORECASE)
                if policy_match:
                    dmarc_analysis['policy'] = policy_match.group(1)
        
        return dmarc_analysis
    
    def _analyze_arc(self, message) -> Dict[str, Any]:
        """
        Analyze ARC (Authenticated Received Chain) headers.
        
        Args:
            message: Email message object
            
        Returns:
            ARC analysis dictionary
        """
        arc_analysis = {
            'status': 'none',
            'chain_count': 0,
            'details': []
        }
        
        # Check for ARC headers
        arc_seal = message.get_all('ARC-Seal') or []
        arc_message_signature = message.get_all('ARC-Message-Signature') or []
        arc_authentication_results = message.get_all('ARC-Authentication-Results') or []
        
        arc_analysis['chain_count'] = max(len(arc_seal), len(arc_message_signature), len(arc_authentication_results))
        
        if arc_analysis['chain_count'] > 0:
            arc_analysis['status'] = 'present'
            arc_analysis['details'].append(f"ARC chain with {arc_analysis['chain_count']} hop(s)")
            
            # Analyze each ARC component
            for i, seal in enumerate(arc_seal):
                instance = self._extract_arc_instance(seal)
                arc_analysis['details'].append(f"ARC-Seal i={instance}: {seal[:100]}...")
            
            for i, sig in enumerate(arc_message_signature):
                instance = self._extract_arc_instance(sig)
                arc_analysis['details'].append(f"ARC-Message-Signature i={instance}: {sig[:100]}...")
        
        return arc_analysis
    
    def _extract_dkim_domain(self, signature: str) -> str:
        """Extract domain from DKIM signature."""
        domain_match = re.search(r'd=([^;]+)', signature)
        return domain_match.group(1) if domain_match else 'unknown'
    
    def _extract_dkim_selector(self, signature: str) -> str:
        """Extract selector from DKIM signature."""
        selector_match = re.search(r's=([^;]+)', signature)
        return selector_match.group(1) if selector_match else 'unknown'
    
    def _extract_arc_instance(self, arc_header: str) -> str:
        """Extract instance number from ARC header."""
        instance_match = re.search(r'i=(\d+)', arc_header)
        return instance_match.group(1) if instance_match else 'unknown'
    
    def _calculate_conclusion(self, spf: Dict, dkim: Dict, dmarc: Dict, arc: Dict) -> str:
        """
        Calculate overall authentication conclusion.
        
        Args:
            spf: SPF analysis results
            dkim: DKIM analysis results
            dmarc: DMARC analysis results
            arc: ARC analysis results
            
        Returns:
            Overall conclusion string
        """
        conclusions = []
        
        # DMARC is the most important
        if dmarc['status'] == 'pass':
            conclusions.append("DMARC PASS")
        elif dmarc['status'] == 'fail':
            conclusions.append("DMARC FAIL")
        
        # SPF results
        if spf['status'] == 'pass':
            conclusions.append("SPF PASS")
        elif spf['status'] == 'fail':
            conclusions.append("SPF FAIL")
        elif spf['status'] == 'softfail':
            conclusions.append("SPF SOFTFAIL")
        
        # DKIM results
        if dkim['status'] == 'pass':
            conclusions.append("DKIM PASS")
        elif dkim['status'] == 'fail':
            conclusions.append("DKIM FAIL")
        
        # ARC status
        if arc['status'] == 'present':
            conclusions.append("ARC PRESENT")
        
        # Overall assessment
        if dmarc['status'] == 'pass':
            return "AUTHENTICATED: " + " | ".join(conclusions)
        elif spf['status'] == 'pass' and dkim['status'] == 'pass':
            return "LIKELY AUTHENTIC: " + " | ".join(conclusions)
        elif spf['status'] == 'fail' or dkim['status'] == 'fail' or dmarc['status'] == 'fail':
            return "FAILED AUTHENTICATION: " + " | ".join(conclusions)
        else:
            return "AUTHENTICATION INCOMPLETE: " + " | ".join(conclusions) if conclusions else "NO AUTHENTICATION"
    
    def _calculate_confidence_score(self, spf: Dict, dkim: Dict, dmarc: Dict) -> int:
        """Calculate confidence score (0-100)."""
        score = 0
        
        # DMARC scoring (most important)
        if dmarc['status'] == 'pass':
            score += 50
        elif dmarc['status'] == 'fail':
            score -= 30
        
        # SPF scoring
        if spf['status'] == 'pass':
            score += 25
        elif spf['status'] == 'fail':
            score -= 20
        elif spf['status'] == 'softfail':
            score -= 10
        
        # DKIM scoring
        if dkim['status'] == 'pass':
            score += 25
        elif dkim['status'] == 'fail':
            score -= 20
        
        return max(0, min(100, score))
    
    def _generate_security_recommendations(self, spf: Dict, dkim: Dict, dmarc: Dict) -> List[str]:
        """Generate security recommendations based on results."""
        recommendations = []
        
        if spf['status'] in ['fail', 'softfail']:
            recommendations.append("SPF authentication failed - verify sender's IP authorization")
        
        if dkim['status'] == 'fail':
            recommendations.append("DKIM signature validation failed - message may be modified or spoofed")
        
        if dmarc['status'] == 'fail':
            recommendations.append("DMARC policy violation - high risk of spoofing")
        
        if all(auth['status'] in ['unknown', 'none'] for auth in [spf, dkim, dmarc]):
            recommendations.append("No email authentication present - treat with caution")
        
        return recommendations
    
    def _extract_raw_auth_headers(self, message) -> Dict[str, List[str]]:
        """Extract all raw authentication headers."""
        return {
            'Authentication-Results': message.get_all('Authentication-Results') or [],
            'Received-SPF': [message.get('Received-SPF')] if message.get('Received-SPF') else [],
            'DKIM-Signature': message.get_all('DKIM-Signature') or [],
            'ARC-Seal': message.get_all('ARC-Seal') or [],
            'ARC-Message-Signature': message.get_all('ARC-Message-Signature') or [],
            'ARC-Authentication-Results': message.get_all('ARC-Authentication-Results') or []
        }