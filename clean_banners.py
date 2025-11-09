"""
Clean, minimal banner system for EmailAnalyzer.
"""


def print_section_header(title: str, icon: str = "📧") -> None:
    """
    Print a clean section header.
    
    Args:
        title: Section title
        icon: Icon/emoji for the section
    """
    print(f"\n{icon} {title.upper()}")
    print("=" * (len(title) + 3))


def print_introduction():
    """Print application introduction."""
    print("""
╔══════════════════════════════════════════════════════════╗
║                    📧 EMAIL ANALYZER                     ║ 
║          Advanced Email Security Analysis Tool           ║
║             https://github.com/jubeenshah              ║
╚══════════════════════════════════════════════════════════╝
    """)


def print_analysis_complete():
    """Print analysis completion message."""
    print("""
╔══════════════════════════════════════════════════════════╗
║                   ✅ ANALYSIS COMPLETE                   ║
╚══════════════════════════════════════════════════════════╝
    """)


# Legacy function mappings for backward compatibility
def get_introduction_banner():
    print_introduction()

def get_headers_banner():
    print_section_header("Headers", "📧")

def get_links_banner():
    print_section_header("Links", "🔗")

def get_digests_banner():
    print_section_header("Digests", "🔐")

def get_attachment_banner():
    print_section_header("Attachments", "📎")

def get_investigation_banner():
    print_section_header("Investigation", "🔍")

def get_tracking_banner():
    print_section_header("Tracking Pixels", "👁")

def get_infrastructure_banner():
    print_section_header("Infrastructure", "🏗")

def get_authentication_banner():
    print_section_header("Authentication", "🛡")