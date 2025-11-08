#!/usr/bin/env python3

# Libraries
##############################################################################
from email.parser import HeaderParser, BytesParser
from email import message_from_file,policy
from argparse import ArgumentParser
import sys
import hashlib
import re
import os
import json
from datetime import datetime
from io import BytesIO
from banners import (
    get_introduction_banner,get_headers_banner,get_links_banner,
    get_digests_banner,get_attachment_banner,get_investigation_banner
)
from html_generator import generate_table_from_json
##############################################################################

# Global Values
##############################################################################
# Supported File Types
SUPPORTED_FILE_TYPES = ["eml"]

# Supported Output File Types
SUPPORTED_OUTPUT_TYPES = ["json","html"]

# REGEX
# Comprehensive HTML href regex that handles various quote styles and whitespace
LINK_REGEX = r'''(?i)href\s*=\s*(?:
    "([^"]*)"           |  # Double quotes
    '([^']*)'           |  # Single quotes  
    ([^\s>]+)              # No quotes (until space or >)
)'''
URL_REGEX = r'https?://[^\s<>"{}|\\^`\[\]]+'
MAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

# Date Format
DATE_FORMAT = "%B %d, %Y - %H:%M:%S"

# Terminal Column Size
TER_COL_SIZE = 60
##############################################################################

# Functions
##############################################################################
def get_headers(msg, investigation):
    '''Get Headers from mail message object'''
    # Create JSON data
    data = json.loads('{"Headers":{"Data":{},"Investigation":{}}}')
    # Put Header data to JSON
    for k,v in msg.items():
        data["Headers"]["Data"][k.lower()] = v.replace('\t', '').replace('\n', '')
    
    # To get all 'Received' headers
    if data["Headers"]["Data"].get('received'):
        data["Headers"]["Data"]["received"] = ' '.join(msg.get_all('Received')).replace('\t', '').replace('\n', '')

    # If investigation requested
    if investigation:
        # X-Sender-Ip Investigation
        if data["Headers"]["Data"].get("x-sender-ip"):
            data["Headers"]["Investigation"]["X-Sender-Ip"] = {
                "Virustotal":f'https://www.virustotal.com/gui/search/{data["Headers"]["Data"]["x-sender-ip"]}',
                "Abuseipdb":f'https://www.abuseipdb.com/check/{data["Headers"]["Data"]["x-sender-ip"]}'
            }
        
        # Reply To - From Investigation (Spoof Check)
        if data["Headers"]["Data"].get("reply-to") and data["Headers"]["Data"].get("from"):
            # Get Reply-To Address
            replyto_matches = re.findall(
                    MAIL_REGEX, data["Headers"]["Data"]["reply-to"]
            )
            
            # Get From Address
            mailfrom_matches = re.findall(
                    MAIL_REGEX, data["Headers"]["Data"]["from"]
            )
            
            # Check if we found valid email addresses in both headers
            if replyto_matches and mailfrom_matches:
                replyto = replyto_matches[0]
                mailfrom = mailfrom_matches[0]
                
                # Check if From & Reply-To is same
                if replyto == mailfrom:
                    conclusion = "Reply Address and From Address is SAME."
                else:
                    conclusion = "Reply Address and From Address is NOT Same. This mail may be SPOOFED."
                
                # Write data to JSON
                data["Headers"]["Investigation"]["Spoof Check"] = {
                    "Reply-To": replyto,
                    "From": mailfrom,
                    "Conclusion": conclusion
                }
            else:
                # Handle case where email regex didn't find valid addresses
                replyto = replyto_matches[0] if replyto_matches else "No valid email found"
                mailfrom = mailfrom_matches[0] if mailfrom_matches else "No valid email found"
                
                data["Headers"]["Investigation"]["Spoof Check"] = {
                    "Reply-To": replyto,
                    "From": mailfrom,
                    "Conclusion": "Cannot determine spoof status - invalid or missing email addresses"
                }

    return data

def get_digests(msg, filename : str, investigation):
    '''Get Hash value of mail'''
    with open(filename, 'rb') as f:
        eml_file    = f.read()
        file_md5    = hashlib.md5(eml_file).hexdigest()
        file_sha1   = hashlib.sha1(eml_file).hexdigest()
        file_sha256 = hashlib.sha256(eml_file).hexdigest()

    # Get content as string for hashing
    content_str = str(msg)
    content_md5     = hashlib.md5(content_str.encode("utf-8")).hexdigest()
    content_sha1    = hashlib.sha1(content_str.encode("utf-8")).hexdigest()
    content_sha256  = hashlib.sha256(content_str.encode("utf-8")).hexdigest()

    # Create JSON data
    data = json.loads('{"Digests":{"Data":{},"Investigation":{}}}')

    # Write Data to JSON
    data["Digests"]["Data"]["File MD5"]         = file_md5
    data["Digests"]["Data"]["File SHA1"]        = file_sha1
    data["Digests"]["Data"]["File SHA256"]      = file_sha256
    data["Digests"]["Data"]["Content MD5"]      = content_md5
    data["Digests"]["Data"]["Content SHA1"]     = content_sha1
    data["Digests"]["Data"]["Content SHA256"]   = content_sha256

    # If investigation requested
    if investigation:
        data["Digests"]["Investigation"]["File MD5"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{file_md5}"
        }
        data["Digests"]["Investigation"]["File SHA1"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{file_sha1}"
        }
        data["Digests"]["Investigation"]["File SHA256"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{file_sha256}"
        }
        data["Digests"]["Investigation"]["Content MD5"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{content_md5}"
        }
        data["Digests"]["Investigation"]["Content SHA1"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{content_sha1}"
        }
        data["Digests"]["Investigation"]["Content SHA256"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{content_sha256}"
        }
    return data

def get_links(msg, investigation):
    '''Get Links from mail message object'''
    
    # Extract text content from the message
    mail_content = ""
    
    # Get text content from all parts of the message
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                content = part.get_payload(decode=True)
                if content:
                    try:
                        # Try to decode with specified charset or fallback to utf-8
                        charset = part.get_content_charset() or 'utf-8'
                        mail_content += content.decode(charset, errors='ignore') + "\n"
                    except (UnicodeDecodeError, LookupError):
                        # Fallback to latin-1 which can decode any byte sequence
                        mail_content += content.decode('latin-1', errors='ignore') + "\n"
    else:
        # Single part message
        content = msg.get_payload(decode=True)
        if content:
            try:
                charset = msg.get_content_charset() or 'utf-8'
                mail_content = content.decode(charset, errors='ignore')
            except (UnicodeDecodeError, LookupError):
                mail_content = content.decode('latin-1', errors='ignore')

    # Find the Links using both href attributes and plain text URLs
    href_matches = re.findall(LINK_REGEX, mail_content, re.VERBOSE)  # HTML href="..." links
    # The regex returns tuples (double_quote, single_quote, no_quote) - get the non-empty one
    href_links = [match[0] or match[1] or match[2] for match in href_matches]
    
    # Clean up href links - normalize whitespace
    href_links = [re.sub(r'\s+', ' ', link.strip()) for link in href_links if link.strip()]
    
    # Only look for plain text URLs if no href links found or in non-HTML content
    url_links = []
    if not href_links or not any('<' in part for part in mail_content.split('\n')[:5]):  # Heuristic for HTML detection
        url_links = re.findall(URL_REGEX, mail_content)    # Plain text URLs
    
    # Combine both types of links
    all_links = href_links + url_links
    
    # Remove duplicates while preserving order and filter out empty links
    links = []
    seen = set()
    for link in all_links:
        if link and link not in seen:
            links.append(link)
            seen.add(link)

    # Create JSON data
    data = json.loads('{"Links":{"Data":{},"Investigation":{}}}')

    for index,link in enumerate(links,start=1):
        data["Links"]["Data"][str(index)] = link
    
    # If investigation requested
    if investigation:
        for index,link in enumerate(links,start=1):
            # Remove http/s from link
            if "://" in link:
                link = link.split("://")[-1]
            
            data["Links"]["Investigation"][str(index)] = {
                "Virustotal":f"https://www.virustotal.com/gui/search/{link}",
                "Urlscan":f"https://urlscan.io/search/#{link}"
            }
    return data

def get_attachments(filename : str, investigation):
    ''' Get Attachments from eml file'''
    with open(filename, "rb") as f:
        content = f.read()
        # Strip leading whitespace that can interfere with email parsing
        content = content.lstrip()
        msg = BytesParser(policy=policy.default).parse(BytesIO(content))
    
    # Create JSON data
    data = json.loads('{"Attachments":{"Data":{},"Investigation":{}}}')

    # Get Attachments from Mail
    attachments = []
    unnamed_attachment_counter = 1
    
    for attachment in msg.iter_attachments():
        attached_file = {}
        
        # Get filename with fallback for None
        filename = attachment.get_filename()
        if not filename:
            # Check if it's an inline image/content (has Content-ID)
            content_id = attachment.get('Content-ID')
            if content_id:
                # Remove angle brackets if present: <cid123> -> cid123
                cid = content_id.strip('<>')
                filename = f"inline_content_{cid}"
            else:
                # Generate synthetic name based on content type
                content_type = attachment.get_content_type() or "application/octet-stream"
                main_type, sub_type = content_type.split('/', 1)
                filename = f"unnamed_attachment_{unnamed_attachment_counter}.{sub_type}"
                unnamed_attachment_counter += 1
        
        attached_file["filename"] = filename
        attached_file["content_type"] = attachment.get_content_type() or "unknown"
        attached_file["content_id"] = attachment.get('Content-ID', '').strip('<>')
        attached_file["is_inline"] = bool(attachment.get('Content-ID'))
        attached_file["MD5"] = hashlib.md5(attachment.get_payload(decode=True)).hexdigest()
        attached_file["SHA1"] = hashlib.sha1(attachment.get_payload(decode=True)).hexdigest()
        attached_file["SHA256"] = hashlib.sha256(attachment.get_payload(decode=True)).hexdigest()
        attachments.append(attached_file)

    for index,attachment in enumerate(attachments,start=1):
        # Create a safe display name that includes type info
        display_name = attachment["filename"]
        if attachment["is_inline"]:
            display_name = f"[INLINE] {display_name}"
        data["Attachments"]["Data"][str(index)] = display_name

    # If investigation requested
    if investigation:
        for index,attachment in enumerate(attachments,start=1):
            # Use a safe key for investigation that includes index to avoid collisions
            investigation_key = f"{index}_{attachment['filename']}"
            
            investigation_data = {
                "Virustotal":{
                    "Name Search":f'https://www.virustotal.com/gui/search/{attachment["filename"]}',
                    "MD5":f'https://www.virustotal.com/gui/search/{attachment["MD5"]}',
                    "SHA1":f'https://www.virustotal.com/gui/search/{attachment["SHA1"]}',
                    "SHA256":f'https://www.virustotal.com/gui/search/{attachment["SHA256"]}'
                }
            }
            
            # Add additional metadata for context
            investigation_data["Metadata"] = {
                "Content-Type": attachment["content_type"],
                "Is-Inline": attachment["is_inline"]
            }
            
            if attachment["content_id"]:
                investigation_data["Metadata"]["Content-ID"] = attachment["content_id"]
            
            data["Attachments"]["Investigation"][investigation_key] = investigation_data

    return data
##############################################################################

# Pretty Print Function
##############################################################################
def print_data(data):
    # Inroduction Banner
    get_introduction_banner()

    # Print Headers
    if data["Analysis"].get("Headers"):
        # Print Banner
        get_headers_banner()

        # Print Headers
        for key,val in data["Analysis"]["Headers"]["Data"].items():
            print("_"*TER_COL_SIZE)
            print(f"[{key}]")
            print(val)
            print("_"*TER_COL_SIZE)
        
        # Print Investigation
        if data["Analysis"]["Headers"].get("Investigation"):
            get_investigation_banner() # Print Banner
            for key,val in data["Analysis"]["Headers"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print(f"[{key}]")
                for k,v in val.items():
                    print(f"{k}:\n{v}\n")
                print("_"*TER_COL_SIZE)
    
    # Print Digests
    if data["Analysis"].get("Digests"):
        # Print Banner
        get_digests_banner()

        for key,val in data["Analysis"]["Digests"]["Data"].items():
            print("_"*TER_COL_SIZE)
            print(f"[{key}]")
            print(val)
            print("_"*TER_COL_SIZE)
        
        # Print Investigation
        if data["Analysis"]["Digests"].get("Investigation"):
            get_investigation_banner() # Print Banner
            for key,val in data["Analysis"]["Digests"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print(f"[{key}]")
                for k,v in val.items():
                    print(f"{k}:\n{v}\n")
                print("_"*TER_COL_SIZE)

    # Print Links
    if data["Analysis"].get("Links"):
        # Print Banner
        get_links_banner()

        # Print Links
        for key,val in data["Analysis"]["Links"]["Data"].items():
            print(f"[{key}]->{val}")
        
        # Print Investigation
        if data["Analysis"]["Links"].get("Investigation"):
            get_investigation_banner() # Print Banner
            # Print Links with Investigation tools
            for key,val in data["Analysis"]["Links"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print(f"[{key}]")
                for k,v in val.items():
                    print(f"{k}:\n{v}\n")
                print("_"*TER_COL_SIZE)
    
    # Print Attachments
    if data["Analysis"].get("Attachments"):
        # Print Banner
        get_attachment_banner()

        # Print Attachments
        for key,val in data["Analysis"]["Attachments"]["Data"].items():
            print(f"[{key}]->{val}")
            print("_"*TER_COL_SIZE)
        
        # Print Investigation
        if data["Analysis"]["Attachments"].get("Investigation"):
            get_investigation_banner() # Print Banner
            for key,val in data["Analysis"]["Attachments"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print(f"- {key}\n")
                for k,v in val.items():
                    print(f"{k}:")
                    for a,b in v.items():
                        print(f"[{a}]->{b}")
                print("_"*TER_COL_SIZE)
##############################################################################

# Write to File Function
##############################################################################
def write_to_file(filename, data):
    # Get File Format
    file_format = filename.split('.')[-1]
    file_format = file_format.lower()
    
    if file_format == "json":
        with open(filename, 'w', encoding="utf-8") as file:
            json.dump(data, file, indent=4)
    elif file_format == "html":
        with open(filename, 'w', encoding="utf-8") as file:
            html_data = generate_table_from_json(data)
            file.write(html_data)
    # if Output File Format is NOT Supported
    # file_format is NOT in SUPPORTED_FILE_TYPES
    else:
        print(f"{filename} file format not supported for output")
        sys.exit(-1) #Exit with error code
##############################################################################

# Main
##############################################################################
description = ""
if __name__ == '__main__':
    parser = ArgumentParser(
        description=description
    )
    parser.add_argument(
        "-f",
        "--filename",
        type=str,
        help="Name of the EML file",
        required=True
    )
    parser.add_argument(
        "-H",
        "--headers",
        help="To get the Headers of the Email",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-d",
        "--digests",
        help="To get the Digests of the Email",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-l",
        "--links",
        help="To get the Links from the Email",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-a",
        "--attachments",
        help="To get the Attachments from the Email",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-i",
        "--investigate",
        help="Activate if you want an investigation",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Name of the Output file (Only HTML or JSON format supported)",
        required=False
    )
    args = parser.parse_args()

    # If we are in a terminal
    if sys.stdout.isatty():
        # Get Terminal Column Size
        terminal_size = os.get_terminal_size()
        # Set Terminal Column Size
        TER_COL_SIZE = terminal_size.columns

    # Filename
    if args.filename:
        # Get Filename
        filename = str(args.filename)
        # Get File Format
        file_format = filename.split('.')[-1]
        if file_format not in SUPPORTED_FILE_TYPES:
            print(f"{file_format} file format not supported")
            sys.exit(-1) #Exit with error code
    
    # Parse the email file
    with open(filename, "rb") as file:
        content = file.read()
        # Strip leading whitespace that can interfere with email parsing
        content = content.lstrip()
        msg = BytesParser(policy=policy.default).parse(BytesIO(content))

    # Create JSON data
    app_data = json.loads('{"Information": {}, "Analysis":{}}')
    app_data["Information"]["Project"] = {
        "Name":"EmailAnalyzer",
        "Url":"https://github.com/keraattin/EmailAnalyzer",
        "Version": "2.0",
    }
    app_data["Information"]["Scan"] = {
        "Filename": filename,
        "Generated": str(datetime.now().strftime(DATE_FORMAT))
    }
    
    # List of Arguments
    arg_list = [args.headers, args.digests, args.links, args.attachments]

    # Check if any argument given
    if any(arg_list):
        # Headers
        if args.headers:
            # Get Headers
            headers = get_headers(msg, args.investigate)
            app_data["Analysis"].update(headers)

        # Digests
        if args.digests:
            # Get Digests
            digests = get_digests(msg, filename, args.investigate)
            app_data["Analysis"].update(digests)

        # Links
        if args.links:
            # Get & Print Links
            links = get_links(msg, args.investigate)
            app_data["Analysis"].update(links)
        
        # Attachments
        if args.attachments:
            # Get Attachments 
            attachments = get_attachments(filename, args.investigate)
            app_data["Analysis"].update(attachments)
        
        # If write to file requested
        if args.output:
            output_filename = str(args.output) # Filename
            write_to_file(output_filename, app_data)
            get_introduction_banner()
            print(f"Your data has been written to the {output_filename}")
        else:
            # Print data to Terminal
            print_data(app_data)
            
    else:
        # If no argument given then run all processes
        investigate = True
        # Get Headers
        headers = get_headers(msg, investigate)
        app_data["Analysis"].update(headers)

        # Get Digests
        digests = get_digests(msg, filename, investigate)
        app_data["Analysis"].update(digests)

        # Get & Print Links
        links = get_links(msg, investigate)
        app_data["Analysis"].update(links)
        
        # Get Attachments 
        attachments = get_attachments(filename, investigate)
        app_data["Analysis"].update(attachments)

        # If write to file requested
        if args.output:
            output_filename = str(args.output) # Filename
            write_to_file(output_filename, app_data)
            get_introduction_banner()
            print(f"Your data has been written to the {output_filename}")
        else:
            # Print data to Terminal
            print_data(app_data)
##############################################################################
