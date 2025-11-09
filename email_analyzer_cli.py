#!/usr/bin/env python3
"""
Email Analyzer - Comprehensive email security analysis tool.

Refactored object-oriented version with modular analyzer components.
Original work by keraattin/EmailAnalyzer, enhanced and refactored by jubeenshah.
"""

import argparse
import sys
import os
from pathlib import Path

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from email_analyzer import EmailAnalyzer
from clean_banners import print_introduction


def main():
    """Main entry point for the Email Analyzer CLI."""
    
    parser = argparse.ArgumentParser(
        description='Comprehensive Email Security Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s file.eml                    # Analyze single file with terminal output
  %(prog)s file.eml -o report.json    # Save results to JSON
  %(prog)s file.eml -o report.html    # Save results to HTML
  %(prog)s target/data/               # Analyze all .eml files in directory
  %(prog)s target/data/ -o reports/   # Analyze directory, save to folder

Analysis includes:
  • Email headers and spoofing detection
  • Authentication (SPF, DKIM, DMARC, ARC)
  • Links and tracking pixels
  • Attachments and file hashes
  • Infrastructure analysis
  • Security recommendations
        """
    )
    
    parser.add_argument(
        'input',
        help='Email file (.eml) or directory containing email files'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file or directory (supports .json, .html formats)'
    )
    
    parser.add_argument(
        '--no-terminal',
        action='store_true',
        help='Suppress terminal output (useful when only saving to file)'
    )
    
    parser.add_argument(
        '--analysis',
        nargs='+',
        choices=['headers', 'auth', 'links', 'attachments', 'tracking', 'infrastructure', 'digests'],
        help='Specify which analysis modules to run (default: all)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='EmailAnalyzer 2.0 (Refactored OOP Version)'
    )
    
    args = parser.parse_args()
    
    # Validate input
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input path '{args.input}' does not exist.")
        sys.exit(1)
    
    # Create analyzer instance
    analyzer = EmailAnalyzer()
    
    # Configure analysis modules if specified
    if args.analysis:
        analyzer.configure_analysis(args.analysis)
    
    try:
        if input_path.is_file():
            # Analyze single file
            if not args.no_terminal:
                print_introduction()
                print(f"Analyzing: {input_path}")
                print("=" * 60)
            
            results = analyzer.analyze_file(str(input_path))
            
            # Output results
            if not args.no_terminal:
                analyzer.output_formatter.print_terminal_output(results)
            
            if args.output:
                output_path = Path(args.output)
                analyzer.output_formatter.save_results(results, str(output_path))
        
        elif input_path.is_dir():
            # Analyze directory
            eml_files = list(input_path.glob('*.eml'))
            
            if not eml_files:
                print(f"No .eml files found in directory: {input_path}")
                sys.exit(1)
            
            if not args.no_terminal:
                print_introduction()
                print(f"Found {len(eml_files)} email files in: {input_path}")
                print("=" * 60)
            
            # Analyze all files
            all_results = analyzer.analyze_all(eml_files)
            
            # Handle output
            if args.output:
                output_path = Path(args.output)
                
                if output_path.suffix in ['.json', '.html']:
                    # Single file output - combine all results
                    combined_results = {
                        "EmailAnalyzer": "Batch Analysis Results",
                        "TotalFiles": len(all_results),
                        "Files": all_results
                    }
                    analyzer.output_formatter.save_results(combined_results, str(output_path))
                    
                else:
                    # Directory output - individual files
                    output_path.mkdir(exist_ok=True)
                    
                    for filename, results in all_results.items():
                        safe_name = Path(filename).stem.replace(' ', '_')
                        output_file = output_path / f"{safe_name}_analysis.json"
                        analyzer.output_formatter.save_results(results, str(output_file))
                    
                    print(f"Saved {len(all_results)} analysis reports to: {output_path}")
            
            # Terminal output for batch analysis
            if not args.no_terminal:
                print(f"\nBatch Analysis Summary:")
                print(f"Files analyzed: {len(all_results)}")
                print(f"Results saved to: {args.output if args.output else 'terminal only'}")
        
        else:
            print(f"Error: '{args.input}' is neither a file nor a directory.")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}")
        if not args.no_terminal:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()