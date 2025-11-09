# EmailAnalyzer - Comprehensive Email Security Analysis Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

A powerful, object-oriented email analysis tool for security researchers, IT professionals, and digital forensics experts. This refactored version provides comprehensive analysis of email messages including authentication verification, tracking detection, and security assessment.

## 🙏 Acknowledgments

This project is based on the excellent work by [keraattin/EmailAnalyzer](https://github.com/keraattin/EmailAnalyzer). We thank the original author for creating the foundation that made this enhanced version possible. This refactored version adds object-oriented architecture, enhanced authentication analysis, and improved modularity while maintaining the core functionality.

## ✨ Features

### Core Analysis Capabilities
- **Email Headers Analysis**: Complete header parsing with spoofing detection
- **Authentication Verification**: SPF, DKIM, DMARC, and ARC analysis with confidence scoring
- **Link Analysis**: URL extraction and investigation with tracking detection  
- **Attachment Analysis**: File type detection, hash generation, and security assessment
- **Tracking Pixel Detection**: Identify marketing and surveillance tracking elements
- **Infrastructure Analysis**: Email routing and classification analysis
- **Security Recommendations**: Automated risk assessment and mitigation advice

### Technical Features
- **Object-Oriented Architecture**: Modular analyzer classes for maintainability
- **Multiple Output Formats**: Terminal display, JSON, and HTML reports
- **Batch Processing**: Analyze multiple emails or entire directories
- **Extensible Design**: Easy to add new analysis modules
- **Investigation Links**: Automatic generation of OSINT investigation URLs

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- No external dependencies required (uses standard library only)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/jubeenshah/EmailAnalyzer.git
cd EmailAnalyzer

# Make the script executable
chmod +x email_analyzer_cli.py

# Run analysis on a sample email
python email_analyzer_cli.py target/data/sample.eml
```

## 📖 Usage

### Basic Usage

```bash
# Analyze a single email file
python email_analyzer_cli.py email.eml

# Save results to JSON
python email_analyzer_cli.py email.eml -o report.json

# Save results to HTML
python email_analyzer_cli.py email.eml -o report.html

# Analyze all emails in a directory
python email_analyzer_cli.py target/data/

# Batch analysis with individual reports
python email_analyzer_cli.py target/data/ -o reports/
```

### Advanced Options

```bash
# Suppress terminal output (file output only)
python email_analyzer_cli.py email.eml -o report.json --no-terminal

# Run specific analysis modules only
python email_analyzer_cli.py email.eml --analysis headers auth links

# Available analysis modules:
# headers, auth, links, attachments, tracking, infrastructure, digests
```

### Programmatic Usage

```python
from email_analyzer import EmailAnalyzer

# Create analyzer instance
analyzer = EmailAnalyzer()

# Analyze a single file
results = analyzer.analyze_file('email.eml')

# Print results to terminal
analyzer.output_formatter.print_terminal_output(results)

# Save to file
analyzer.output_formatter.save_results(results, 'report.json')

# Batch analysis
import glob
email_files = glob.glob('*.eml')
all_results = analyzer.analyze_all(email_files)
```

## 🔍 Analysis Modules

### Header Analyzer
- Complete email header parsing
- Sender spoofing detection
- IP address investigation links
- Header integrity validation

### Authentication Analyzer  
- **SPF**: Sender Policy Framework verification
- **DKIM**: DomainKeys Identified Mail signature validation
- **DMARC**: Domain-based Message Authentication, Reporting & Conformance
- **ARC**: Authenticated Received Chain analysis
- Confidence scoring and security recommendations

### Link Analyzer
- URL extraction from email content
- Link validation and categorization
- Investigation links for threat intelligence
- Malicious URL detection indicators

### Attachment Analyzer
- File type and MIME type identification
- Hash generation (MD5, SHA1, SHA256)
- File size analysis
- VirusTotal integration links

### Tracking Analyzer
- Marketing tracking pixel detection
- Web beacon identification
- Known tracking service recognition
- Privacy analysis

### Infrastructure Analyzer
- Email routing path analysis
- Message classification (bulk, transactional, suspicious)
- Infrastructure fingerprinting
- Delivery path validation

### Digest Analyzer
- Content hashing for forensics
- File integrity verification
- Investigation hash lookups

## 📊 Output Formats

### Terminal Output
Clean, organized display with emoji icons and color coding for easy reading.

### JSON Output
Structured data format perfect for integration with other tools:

```json
{
    "EmailAnalyzer": "Analysis Results", 
    "FileName": "email.eml",
    "Analysis": {
        "Headers": {...},
        "Auth": {...},
        "Links": {...},
        "Attachments": {...}
    }
}
```

### HTML Output
Professional web-based reports with interactive tables and formatted data display.

## 🏗️ Architecture

The refactored codebase follows object-oriented principles with a modular design:

```
EmailAnalyzer/
├── email_analyzer_cli.py          # Main CLI entry point
├── email_analyzer.py              # Core orchestrator class
├── output_formatter.py            # Output formatting and display
├── clean_banners.py              # Clean UI banner system  
├── analyzers/                     # Analysis modules
│   ├── __init__.py
│   ├── base_analyzer.py          # Abstract base class
│   ├── header_analyzer.py        # Header analysis
│   ├── authentication_analyzer.py # SPF/DKIM/DMARC/ARC
│   ├── link_analyzer.py          # URL analysis
│   ├── attachment_analyzer.py    # File analysis
│   ├── tracking_analyzer.py      # Tracking detection
│   ├── infrastructure_analyzer.py # Routing analysis
│   └── digest_analyzer.py        # Hash generation
└── target/                       # Sample data and reports
```

## 🔧 Development

### Adding New Analyzers

To create a new analyzer module:

1. Inherit from `BaseAnalyzer`
2. Implement the `analyze()` method
3. Add to `analyzers/__init__.py`
4. Update the `EmailAnalyzer` orchestrator

```python
from analyzers.base_analyzer import BaseAnalyzer

class CustomAnalyzer(BaseAnalyzer):
    def analyze(self, message, filename=None):
        data = self._create_data_structure()
        # Your analysis logic here
        data['Data'] = {'custom_field': 'custom_value'}
        return data
```

### Testing

The project includes sample email files in `target/data/` for testing various scenarios including:
- SPF/DKIM authentication
- SPAM headers and routing
- Different email clients and services

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Areas for Contribution
- Additional tracking service patterns
- New authentication mechanisms
- Enhanced attachment analysis
- Performance optimizations
- Additional output formats

## 🛡️ Security Note

This tool is designed for legitimate security analysis and digital forensics. Always ensure you have proper authorization before analyzing email messages that don't belong to you.

## 📚 References

- [RFC 5322](https://tools.ietf.org/html/rfc5322) - Internet Message Format
- [RFC 7208](https://tools.ietf.org/html/rfc7208) - Sender Policy Framework (SPF)
- [RFC 6376](https://tools.ietf.org/html/rfc6376) - DomainKeys Identified Mail (DKIM)
- [RFC 7489](https://tools.ietf.org/html/rfc7489) - Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- [RFC 8617](https://tools.ietf.org/html/rfc8617) - Authenticated Received Chain (ARC)

## 📞 Support

For questions, issues, or contributions, please open an issue on the GitHub repository.

---

**Original Project**: [keraattin/EmailAnalyzer](https://github.com/keraattin/EmailAnalyzer)  
**Enhanced Version**: [jubeenshah/EmailAnalyzer](https://github.com/jubeenshah/EmailAnalyzer)