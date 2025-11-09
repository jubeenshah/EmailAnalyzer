import json
from html import escape

def generate_headers_section(headers):
    # Data
    ######################################################################
    html = """
        <h2 id="headers-section" style="text-align: center;"><i class="fa-solid fa-code"></i> Headers</h2>
        <hr>
        <h3 id="headers-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in headers["Data"].items():
        # Populate table rows
        html += f"<tr><td>{ str(key) }</td><td>{ escape(str(value)) }</td></tr>"
        
    html += """
        </tbody>
    </table>
    """
    ######################################################################
    
    # Investigation
    ######################################################################
    html += """
        <h3 id="headers-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <div class="row">
    """
    for index,values in headers["Investigation"].items():
        # Populate table rows
        html += """
        <div class="col-md-4">
            <div class="jumbotron">
                <h3>{}</h3><hr>
        """.format(index)
        for k,v in values.items():
            html += f"<br><b>{k}:<br></b>{v}"
        
        html += """
            </div>
        </div>
        """

    html += "</div><hr>"
    return html
    ######################################################################

def generate_links_section(links):
    # Data
    ######################################################################
    html = """
        <h2 id="links-section" style="text-align: center;"><i class="fa-solid fa-link"></i> Links</h2>
        <hr>
        <h3 id="links-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in links["Data"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>{}</td>".format(key,value)
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="links-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for index,values in links["Investigation"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>".format(index)
        for k,v in values.items():
            html += f"<b><a href='{v}' target='_blank'>{k} Scan</a></b>&nbsp;&nbsp;"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_attachment_section(attachments):
    # Data
    ######################################################################
    html = """
        <h2 id="attachments-section" style="text-align: center;"><i class="fa-solid fa-paperclip"></i> Attachments</h2>
        <hr>
        <h3 id="attachments-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in attachments["Data"].items():
        # Populate table rows
        html += "<tr>"
        if isinstance(value, dict):
            # Handle attachment data which is a nested dictionary
            html += f"<td>{key}</td><td>"
            for subkey, subvalue in value.items():
                html += f"<b>{subkey}:</b> {subvalue}<br>"
            html += "</td>"
        else:
            # Handle simple status message or other non-dict values  
            html += "<td>{}</td><td>{}</td>".format(key,value)
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="attachments-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for index,values in attachments["Investigation"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>".format(index)
        for k,v in values.items():
            if isinstance(v, dict):
                for x,y in v.items():
                    html += f"<b><a href='{y}' target='_blank'>{x} Scan({k})</a></b><br>"
            else:
                # v is a simple value like URL string or SHA256 hash
                html += f"<b>{k}:</b> {v}<br>"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_digest_section(digests):
    # Data
    ######################################################################
    html = """
        <h2 id="digests-section" style="text-align: center;"><i class="fa-solid fa-hashtag"></i> Digests</h2>
        <hr>
        <h3 id="digests-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in digests["Data"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>{}</td>".format(key,value)
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="digests-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for index,values in digests["Investigation"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>".format(index)
        for k,v in values.items():
            html += f"<b><a href='{v}' target='_blank'>{k} scan</a></b><br>"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_tracking_section(tracking_pixels):
    # Data
    ######################################################################
    html = """
        <h2 id="tracking-section" style="text-align: center;"><i class="fa-solid fa-eye"></i> Tracking Pixels</h2>
        <hr>
        <h3 id="tracking-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in tracking_pixels["Data"].items():
        # Populate table rows
        html += "<tr>"
        if key == "items" and isinstance(value, list):
            # Handle tracking pixel items list safely
            html += f"<td>{escape(str(key))}</td><td>"
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    html += f"<div class='tracking-pixel-item' style='margin-bottom: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 5px;'>"
                    html += f"<strong>Tracking Pixel #{i+1}</strong><br>"
                    html += f"<strong>URL:</strong> <code>{escape(item.get('url', 'N/A'))}</code><br>"
                    html += f"<strong>Provider:</strong> {escape(item.get('provider', 'N/A'))}<br>"
                    html += f"<strong>Reason:</strong> {escape(item.get('reason', 'N/A'))}<br>"
                    if 'tag' in item:
                        # Display the HTML tag as escaped text, not as executable HTML
                        html += f"<strong>HTML Tag:</strong> <code>{escape(item['tag'])}</code><br>"
                    html += "</div>"
                else:
                    html += f"<div>{escape(str(item))}</div>"
            html += "</td>"
        else:
            # Handle other data safely
            html += f"<td>{escape(str(key))}</td><td>{escape(str(value))}</td>"
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="tracking-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Provider</th>
                    <th>Reasons</th>
                </tr>
            </thead>
        <tbody>
    """
    for url, details in tracking_pixels["Investigation"].items():
        # Populate table rows with tracking pixel details
        html += "<tr>"
        html += f"<td><a href='{url}' target='_blank'>{url}</a></td>"
        html += f"<td>{details.get('provider', 'Unknown')}</td>"
        html += f"<td>{', '.join(details.get('reasons', []))}</td>"
        html += "</tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_infrastructure_section(infrastructure):
    # Data
    ######################################################################
    html = """
        <h2 id="infrastructure-section" style="text-align: center;"><i class="fa-solid fa-server"></i> Infrastructure</h2>
        <hr>
        <h3 id="infrastructure-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in infrastructure["Data"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>{}</td>".format(key.replace('_', ' ').title(),value)
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="infrastructure-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Component</th>
                    <th>Details</th>
                </tr>
            </thead>
        <tbody>
    """
    
    # Handle different types of investigation data
    if infrastructure.get("Investigation"):
        for key, details in infrastructure["Investigation"].items():
            html += "<tr>"
            if key.startswith("ip_"):
                # IP address details
                html += f"<td><strong>IP Analysis {key.split('_')[1]}</strong></td>"
                html += "<td>"
                html += f"<strong>IP:</strong> {details.get('IP_Address', 'N/A')}<br>"
                html += f"<strong>ASN:</strong> {details.get('ASN', 'N/A')}<br>"
                html += f"<strong>Organization:</strong> {details.get('Organization', 'N/A')}<br>"
                html += f"<strong>Country:</strong> {details.get('Country', 'N/A')}<br>"
                html += f"<a href='{details.get('VirusTotal', '#')}' target='_blank'>VirusTotal Analysis</a> | "
                html += f"<a href='{details.get('AbuseIPDB', '#')}' target='_blank'>AbuseIPDB Check</a>"
                html += "</td>"
            elif key == "classification_details":
                # Classification details
                html += "<td><strong>Classification Analysis</strong></td>"
                html += "<td>"
                html += f"<strong>Primary:</strong> {details.get('Primary_Classification', 'N/A')}<br>"
                if details.get('Evidence'):
                    html += "<strong>Evidence:</strong><ul>"
                    for evidence in details['Evidence']:
                        html += f"<li>{evidence}</li>"
                    html += "</ul>"
                if details.get('Confidence_Breakdown'):
                    html += "<strong>Confidence Scores:</strong><ul>"
                    for provider, score in details['Confidence_Breakdown'].items():
                        html += f"<li>{provider.title()}: {score}</li>"
                    html += "</ul>"
                html += "</td>"
            elif key == "routing_analysis":
                # Routing analysis
                html += "<td><strong>Routing Analysis</strong></td>"
                html += "<td>"
                html += f"<strong>Return Path:</strong> {details.get('Return_Path', 'N/A')}<br>"
                html += f"<strong>Message-ID Domain:</strong> {details.get('Message_ID_Domain', 'N/A')}<br>"
                html += f"<strong>Received Headers:</strong> {details.get('Received_Headers_Count', 'N/A')}<br>"
                html += f"<strong>Unique IPs:</strong> {details.get('Unique_IPs_Found', 'N/A')}<br>"
                if details.get('IPs_Analyzed'):
                    html += f"<strong>IPs Analyzed:</strong> {', '.join(details['IPs_Analyzed'])}"
                html += "</td>"
            html += "</tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_authentication_section(auth):
    # Data
    ######################################################################
    html = """
        <h2 id="auth-section" style="text-align: center;"><i class="fa-solid fa-shield-halved"></i> Authentication</h2>
        <hr>
        <h3 id="auth-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Result</th>
                </tr>
            </thead>
        <tbody>
    """
    
    # Add authentication results with icons and coloring
    auth_data = auth["Data"]
    
    # SPF
    spf_result = auth_data.get("SPF", "none")
    spf_icon = "✅" if "pass" in spf_result else "❌" if "fail" in spf_result else "⚠️"
    html += f"<tr><td><strong>SPF</strong></td><td>{spf_icon} {spf_result}</td></tr>"
    
    # DKIM  
    dkim_result = auth_data.get("DKIM", "none")
    dkim_icon = "✅" if "pass" in dkim_result else "❌" if "fail" in dkim_result else "⚠️"
    html += f"<tr><td><strong>DKIM</strong></td><td>{dkim_icon} {dkim_result}</td></tr>"
    
    # DMARC
    dmarc_result = auth_data.get("DMARC", "none") 
    dmarc_icon = "✅" if "pass" in dmarc_result else "❌" if "fail" in dmarc_result else "⚠️"
    html += f"<tr><td><strong>DMARC</strong></td><td>{dmarc_icon} {dmarc_result}</td></tr>"
    
    # ARC
    arc_present = auth_data.get("ARC_Present", False)
    arc_icon = "🔗" if arc_present else "➖"
    html += f"<tr><td><strong>ARC</strong></td><td>{arc_icon} {'Present' if arc_present else 'Not Present'}</td></tr>"
    
    # Overall assessment
    confidence_score = auth_data.get("Confidence_Score", 0)
    conclusion = auth_data.get("Conclusion", "Unknown")
    confidence_icon = "🔒" if confidence_score >= 10 else "🔓" if confidence_score >= 5 else "⚠️"
    
    html += f"<tr><td><strong>Confidence Score</strong></td><td>{confidence_score}</td></tr>"
    html += f"<tr><td><strong>Conclusion</strong></td><td>{confidence_icon} {conclusion}</td></tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="auth-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Component</th>
                    <th>Details</th>
                </tr>
            </thead>
        <tbody>
    """
    
    if auth.get("Investigation"):
        investigation = auth["Investigation"]
        
        # Raw Headers
        if "Raw_Headers" in investigation:
            html += "<tr><td><strong>Raw Headers</strong></td><td>"
            for header, value in investigation["Raw_Headers"].items():
                html += f"<strong>{header.replace('_', '-')}:</strong><br><small>{value}</small><br><br>"
            html += "</td></tr>"
        
        # Confidence Analysis
        if "Confidence_Analysis" in investigation:
            confidence = investigation["Confidence_Analysis"] 
            html += "<tr><td><strong>Confidence Analysis</strong></td><td>"
            html += f"<strong>Level:</strong> {confidence.get('Confidence_Level', 'Unknown')}<br>"
            if confidence.get('Score_Breakdown'):
                html += "<strong>Score Breakdown:</strong><ul>"
                for component, score in confidence['Score_Breakdown'].items():
                    html += f"<li>{component.replace('_', ' ')}: {score}</li>"
                html += "</ul>"
            html += "</td></tr>"
        
        # Parsed Details
        if "Parsed_Details" in investigation:
            parsed = investigation["Parsed_Details"]
            html += "<tr><td><strong>Parsed Details</strong></td><td>"
            
            if parsed.get("SPF_Details"):
                spf = parsed["SPF_Details"] 
                html += f"<strong>SPF:</strong><br>Result: {spf.get('result', 'unknown')}<br>"
                if spf.get('client_ip'):
                    html += f"Client IP: {spf['client_ip']}<br>"
                html += "<br>"
            
            if parsed.get("DKIM_Details"):
                dkim = parsed["DKIM_Details"]
                html += f"<strong>DKIM:</strong><br>"
                if dkim.get('domain'):
                    html += f"Domain: {dkim['domain']}<br>"
                if dkim.get('selector'):
                    html += f"Selector: {dkim['selector']}<br>"
                if dkim.get('algorithm'):
                    html += f"Algorithm: {dkim['algorithm']}<br>"
                html += "<br>"
                    
            if parsed.get("ARC_Analysis", {}).get('present'):
                arc = parsed["ARC_Analysis"]
                html += f"<strong>ARC:</strong><br>"
                html += f"Chain Valid: {arc.get('chain_valid', False)}<br>"
                html += f"Instances: {arc.get('instances', 0)}<br>"
            
            html += "</td></tr>"
        
        # Recommendations
        if investigation.get("Recommendations"):
            html += "<tr><td><strong>Security Recommendations</strong></td><td><ul>"
            for recommendation in investigation["Recommendations"]:
                html += f"<li>{recommendation}</li>"
            html += "</ul></td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_table_from_json(json_obj):
    # Parse JSON object
    data = json_obj["Analysis"]
    info_data = json_obj["Information"]

    # Object Counts
    if data.get("Headers"):
        headers_cnt = len(data["Headers"]["Data"])
        headers_inv_cnt = len(data["Headers"]["Investigation"])
    else:
        headers_cnt = 0
        headers_inv_cnt = 0

    if data.get("Links"):
        links_cnt = len(data["Links"]["Data"])
        links_inv_cnt = len(data["Links"]["Investigation"])
    else:
        links_cnt = 0
        links_inv_cnt = 0

    if data.get("Attachments"):
        attach_cnt = len(data["Attachments"]["Data"])
        attach_inv_cnt = len(data["Attachments"]["Investigation"])
    else:
        attach_cnt = 0
        attach_inv_cnt = 0

    if data.get("Digests"):
        digest_cnt = len(data["Digests"]["Data"])
        digest_inv_cnt = len(data["Digests"]["Investigation"])
    else:
        digest_cnt = 0
        digest_inv_cnt = 0

    if data.get("TrackingPixels"):
        tracking_cnt = len(data["TrackingPixels"]["Data"])
        tracking_inv_cnt = len(data["TrackingPixels"]["Investigation"])
    else:
        tracking_cnt = 0
        tracking_inv_cnt = 0

    if data.get("Infrastructure"):
        infrastructure_cnt = len(data["Infrastructure"]["Data"])
        infrastructure_inv_cnt = len(data["Infrastructure"]["Investigation"]) if data["Infrastructure"].get("Investigation") else 0
    else:
        infrastructure_cnt = 0
        infrastructure_inv_cnt = 0

    if data.get("Auth"):
        auth_cnt = len(data["Auth"]["Data"])
        auth_inv_cnt = len(data["Auth"]["Investigation"]) if data["Auth"].get("Investigation") else 0
    else:
        auth_cnt = 0
        auth_inv_cnt = 0

    # Generate HTML table with Bootstrap classes
    html = f"""
        <head>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/css/bootstrap.min.css">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <script async defer src="https://buttons.github.io/buttons.js"></script>
            <style>
                /* CSS for better text wrapping and URL handling */
                .table td, .table th {{
                    word-break: break-word;
                    word-wrap: break-word;
                    overflow-wrap: break-word;
                    max-width: 300px;
                    vertical-align: top;
                }}
                
                .table {{
                    table-layout: fixed;
                    width: 100%;
                }}
                
                .table th:first-child,
                .table td:first-child {{
                    width: 20%;
                    min-width: 120px;
                }}
                
                .table th:last-child,
                .table td:last-child {{
                    width: 80%;
                }}
                
                code {{
                    word-break: break-all;
                    white-space: pre-wrap;
                    overflow-wrap: anywhere;
                    max-width: 100%;
                    display: inline-block;
                }}
                
                .tracking-pixel-item {{
                    word-break: break-word;
                    overflow-wrap: break-word;
                }}
                
                .tracking-pixel-item code {{
                    max-width: 100%;
                    overflow-wrap: anywhere;
                    white-space: pre-wrap;
                }}
                
                /* Responsive table improvements */
                @media (max-width: 768px) {{
                    .table td, .table th {{
                        font-size: 0.875rem;
                        padding: 0.5rem;
                    }}
                    
                    .table th:first-child,
                    .table td:first-child {{
                        width: 25%;
                    }}
                    
                    .table th:last-child,
                    .table td:last-child {{
                        width: 75%;
                    }}
                }}
            </style>
        </head>

        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <a class="navbar-brand" href="#"><i class="fa fa-envelope"></i> Email Analyzer</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <ul class="navbar-nav mr-auto">
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Headers
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#headers-data-section">Data <span class="badge badge-pill badge-dark">{ headers_cnt }</span></a>
                    <a class="dropdown-item" href="#headers-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ headers_inv_cnt }</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Links
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#links-data-section">Data <span class="badge badge-pill badge-dark">{ links_cnt }</span></a>
                    <a class="dropdown-item" href="#links-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ links_inv_cnt }</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Attachments
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#attachments-data-section">Data <span class="badge badge-pill badge-dark">{ attach_cnt }</span></a>
                    <a class="dropdown-item" href="#attachments-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ attach_inv_cnt }</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Digests
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#digests-data-section">Data <span class="badge badge-pill badge-dark">{ digest_cnt }</span></a>
                    <a class="dropdown-item" href="#digests-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ digest_inv_cnt }</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Tracking Pixels
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#tracking-data-section">Data <span class="badge badge-pill badge-dark">{ tracking_cnt }</span></a>
                    <a class="dropdown-item" href="#tracking-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ tracking_inv_cnt }</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Infrastructure
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#infrastructure-data-section">Data <span class="badge badge-pill badge-dark">{ infrastructure_cnt }</span></a>
                    <a class="dropdown-item" href="#infrastructure-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ infrastructure_inv_cnt }</span></a>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Authentication
                    </a>
                    <div class="dropdown-menu" aria-labelledby="navbarDropdown">
                    <a class="dropdown-item" href="#auth-data-section">Data <span class="badge badge-pill badge-dark">{ auth_cnt }</span></a>
                    <a class="dropdown-item" href="#auth-investigation-section">Investigation <span class="badge badge-pill badge-dark">{ auth_inv_cnt }</span></a>
                    </div>
                </li>
                </ul>
            </div>

            <div class="d-flex">
                <!-- Star -->
                <a class="github-button" href="https://github.com/jubeenshah/EmailAnalyzer" data-icon="octicon-star" data-size="large" data-show-count="true" aria-label="Star jubeenshah/EmailAnalyzer on GitHub">Star</a>
                &nbsp;
                <!-- Fork -->
                <a class="github-button" href="https://github.com/jubeenshah/EmailAnalyzer/fork" data-icon="octicon-repo-forked" data-size="large" data-show-count="true" aria-label="Fork jubeenshah/EmailAnalyzer on GitHub">Fork</a>
                &nbsp;
                <!-- Follow -->
                <a class="github-button" href="https://github.com/jubeenshah" data-size="large" data-show-count="true" aria-label="Follow @jubeenshah on GitHub">Follow @jubeenshah</a>
                &nbsp;
                <!-- Original -->
                <a class="github-button" href="https://github.com/keraattin/EmailAnalyzer" data-icon="octicon-repo" data-size="large" aria-label="Original keraattin/EmailAnalyzer on GitHub">Original</a>
            </div>
        </nav>

        <div class="container-fluid">
        """
    
    html += f"""
        <h2 style="text-align: center;"><i class="fa-solid fa-circle-info"></i> Information</h2>
        <hr>
        <div class="row">
            <div class="col-md-6">
                <h3 style="text-align: center;"><i class="fa-solid fa-diagram-project"></i> Project</h3>
                <table class="table table-bordered table-striped">
                    <tbody>
                        <tr>
                            <td>Name</td>
                            <td>{ info_data["Project"]["Name"] }</td>
                        </tr>
                        <tr>
                            <td>Url</td>
                            <td><a href="{ info_data["Project"]["Url"] }" target='_blank'>{ info_data["Project"]["Url"] }</a></td>
                        </tr>
                        <tr>
                            <td>Version</td>
                            <td>{ info_data["Project"]["Version"] }</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="col-md-6">
                <h3 style="text-align: center;"><i class="fa-solid fa-satellite-dish"></i> Scan</h3>
                <table class="table table-bordered table-striped">
                    <tbody>
                        <tr>
                            <td>Name</td>
                            <td>{ info_data["Scan"]["Filename"] }</td>
                        </tr>
                        <tr>
                            <td>Generated</td>
                            <td>{ info_data["Scan"]["Generated"] }</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    """

    if data.get("Headers"):
        html += generate_headers_section(data["Headers"])
    
    if data.get("Links"):
        html += generate_links_section(data["Links"])

    if data.get("Attachments"):
        html += generate_attachment_section(data["Attachments"])

    if data.get("Digests"):    
        html += generate_digest_section(data["Digests"])
    
    if data.get("TrackingPixels"):
        html += generate_tracking_section(data["TrackingPixels"])
    
    if data.get("Infrastructure"):
        html += generate_infrastructure_section(data["Infrastructure"])
    
    if data.get("Auth"):
        html += generate_authentication_section(data["Auth"])
    
    
    html += """
        </div>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/js/bootstrap.min.js"></script>
    """

    return html


def generate_batch_html_report(batch_results):
    """
    Generate a comprehensive HTML report for multiple email analyses.
    
    Args:
        batch_results: Dictionary containing batch analysis results
        
    Returns:
        HTML string for the comprehensive report
    """
    
    total_files = batch_results.get("TotalFiles", 0)
    files_data = batch_results.get("Files", {})
    
    # Validate files_data
    if not isinstance(files_data, dict):
        return f"<html><body><h1>Error: Invalid batch results format</h1><p>Expected dict, got {type(files_data)}</p><p>Data: {files_data}</p></body></html>"
    
    # Generate navigation menu
    nav_items = []
    file_sections = []
    
    print(f"Debug - About to iterate over files_data.items()")
    for i, (filename, results) in enumerate(files_data.items(), 1):
        print(f"Debug - Processing file {i}: {filename}")
        safe_name = filename.replace('/', '_').replace(' ', '_').replace('.', '_')
        nav_items.append({
            'filename': filename,
            'safe_name': safe_name,
            'index': i
        })
    
    print(f"Debug - nav_items created: {len(nav_items)} items")
    
    html = f"""
        <head>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/css/bootstrap.min.css">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <script async defer src="https://buttons.github.io/buttons.js"></script>
            <style>
                .email-section {{
                    margin-bottom: 3rem;
                    border: 2px solid #dee2e6;
                    border-radius: 0.5rem;
                    padding: 1.5rem;
                }}
                .email-header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 1rem;
                    margin: -1.5rem -1.5rem 1.5rem -1.5rem;
                    border-radius: 0.5rem 0.5rem 0 0;
                }}
                .sticky-nav {{
                    position: sticky;
                    top: 0;
                    z-index: 1000;
                }}
                .analysis-summary {{
                    background: #f8f9fa;
                    padding: 1rem;
                    border-radius: 0.5rem;
                    margin-bottom: 1rem;
                }}
                .quick-stats {{
                    display: flex;
                    justify-content: space-around;
                    flex-wrap: wrap;
                    gap: 1rem;
                }}
                .stat-card {{
                    background: white;
                    padding: 1rem;
                    border-radius: 0.5rem;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    min-width: 120px;
                }}
                
                /* CSS for better text wrapping and URL handling */
                .table td, .table th {{
                    word-break: break-word;
                    word-wrap: break-word;
                    overflow-wrap: break-word;
                    max-width: 300px;
                    vertical-align: top;
                }}
                
                .table {{
                    table-layout: fixed;
                    width: 100%;
                }}
                
                .table th:first-child,
                .table td:first-child {{
                    width: 20%;
                    min-width: 120px;
                }}
                
                .table th:last-child,
                .table td:last-child {{
                    width: 80%;
                }}
                
                code {{
                    word-break: break-all;
                    white-space: pre-wrap;
                    overflow-wrap: anywhere;
                    max-width: 100%;
                    display: inline-block;
                }}
                
                .tracking-pixel-item {{
                    word-break: break-word;
                    overflow-wrap: break-word;
                }}
                
                .tracking-pixel-item code {{
                    max-width: 100%;
                    overflow-wrap: anywhere;
                    white-space: pre-wrap;
                }}
                
                /* Responsive table improvements */
                @media (max-width: 768px) {{
                    .table td, .table th {{
                        font-size: 0.875rem;
                        padding: 0.5rem;
                    }}
                    
                    .table th:first-child,
                    .table td:first-child {{
                        width: 25%;
                    }}
                    
                    .table th:last-child,
                    .table td:last-child {{
                        width: 75%;
                    }}
                }}
            </style>
        </head>

        <nav class="navbar navbar-expand-lg navbar-dark bg-primary sticky-nav">
            <a class="navbar-brand" href="#top"><i class="fa fa-envelope"></i> Email Analyzer - Batch Report</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav mr-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="#summary">Summary</a>
                    </li>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" data-toggle="dropdown">
                            Email Files ({total_files})
                        </a>
                        <div class="dropdown-menu">
    """
    
    # Add navigation items
    for item in nav_items:
        html += f'<a class="dropdown-item" href="#{item["safe_name"]}">{item["index"]}. {item["filename"]}</a>\n'
    
    html += """
                        </div>
                    </li>
                </ul>
                <div class="d-flex">
                    <a class="github-button" href="https://github.com/jubeenshah/EmailAnalyzer" data-icon="octicon-star" data-size="large" aria-label="Star jubeenshah/EmailAnalyzer on GitHub">Star</a>
                    &nbsp;
                    <a class="github-button" href="https://github.com/jubeenshah/EmailAnalyzer/fork" data-icon="octicon-repo-forked" data-size="large" aria-label="Fork jubeenshah/EmailAnalyzer on GitHub">Fork</a>
                </div>
            </div>
        </nav>

        <div class="container-fluid">
            <div id="top"></div>
            
            <!-- Summary Section -->
            <section id="summary" class="mt-4">
                <h1 class="text-center mb-4">
                    <i class="fa-solid fa-chart-line"></i> Batch Email Analysis Report
                </h1>
                
                <div class="analysis-summary">
                    <h2><i class="fa-solid fa-info-circle"></i> Analysis Summary</h2>
                    <div class="quick-stats">
    """
    
    # Calculate summary statistics
    total_links = 0
    total_attachments = 0
    total_tracking_pixels = 0
    authentication_passes = 0
    
    for filename, results in files_data.items():
        if results.get("Analysis"):
            analysis = results["Analysis"]
            
            # Count links
            if analysis.get("Links", {}).get("Data"):
                links_data = analysis["Links"]["Data"]
                if isinstance(links_data, dict):
                    total_links += len([k for k in links_data.keys() if k.isdigit()])
            
            # Count attachments  
            if analysis.get("Attachments", {}).get("Data"):
                attachments_data = analysis["Attachments"]["Data"]
                if isinstance(attachments_data, dict):
                    total_attachments += len([k for k in attachments_data.keys() if "Attachment_" in k])
            
            # Count tracking pixels
            if analysis.get("TrackingPixels", {}).get("Data", {}).get("count"):
                total_tracking_pixels += analysis["TrackingPixels"]["Data"]["count"]
            
            # Count authentication passes
            if analysis.get("Auth", {}).get("Data", {}).get("Conclusion"):
                conclusion = analysis["Auth"]["Data"]["Conclusion"]
                if "AUTHENTICATED" in conclusion or "LIKELY AUTHENTIC" in conclusion:
                    authentication_passes += 1
    
    html += f"""
                        <div class="stat-card">
                            <h3>{total_files}</h3>
                            <p>Emails Analyzed</p>
                        </div>
                        <div class="stat-card">
                            <h3>{total_links}</h3>
                            <p>Total Links</p>
                        </div>
                        <div class="stat-card">
                            <h3>{total_attachments}</h3>
                            <p>Attachments</p>
                        </div>
                        <div class="stat-card">
                            <h3>{total_tracking_pixels}</h3>
                            <p>Tracking Pixels</p>
                        </div>
                        <div class="stat-card">
                            <h3>{authentication_passes}</h3>
                            <p>Auth Passed</p>
                        </div>
                    </div>
                </div>
            </section>
            
            <hr class="my-5">
    """
    
    # Generate individual email sections
    for i, (filename, results) in enumerate(files_data.items(), 1):
        safe_name = filename.replace('/', '_').replace(' ', '_').replace('.', '_')
        
        html += f"""
            <section id="{safe_name}" class="email-section">
                <div class="email-header">
                    <h2><i class="fa-solid fa-envelope"></i> {i}. {escape(filename)}</h2>
                    <p class="mb-0">
                        <a href="#top" class="text-white"><i class="fa-solid fa-arrow-up"></i> Back to Top</a>
                        {f"| <a href='#{nav_items[i]['safe_name']}' class='text-white'><i class='fa-solid fa-arrow-down'></i> Next Email</a>" if i < len(nav_items) else ""}
                    </p>
                </div>
        """
        
        # Check if this is an error result
        if results.get("EmailAnalyzer") == "Error":
            html += f"""
                <div class="alert alert-danger">
                    <h4><i class="fa-solid fa-exclamation-triangle"></i> Analysis Error</h4>
                    <p><strong>Error:</strong> {escape(str(results.get('Error', 'Unknown error')))}</p>
                </div>
            """
        else:
            # Generate the standard analysis report for this email
            if results.get("Analysis"):
                # Create a temporary single-email structure for the existing generator
                single_email_result = {
                    "EmailAnalyzer": "Analysis Results",
                    "FileName": filename,
                    "Analysis": results["Analysis"],
                    "Information": {
                        "Project": {
                            "Name": "EmailAnalyzer",
                            "Url": "https://github.com/jubeenshah/EmailAnalyzer",
                            "Version": "2.0"
                        },
                        "Scan": {
                            "Filename": filename,
                            "Generated": results.get("Information", {}).get("Scan", {}).get("Generated", "Unknown")
                        }
                    }
                }
                
                # Use existing generator functions for individual sections
                analysis = results["Analysis"]
                
                if analysis.get("Headers"):
                    html += generate_headers_section(analysis["Headers"])
                
                if analysis.get("Links"):
                    html += generate_links_section(analysis["Links"])
                
                if analysis.get("Attachments"):
                    html += generate_attachment_section(analysis["Attachments"])
                
                if analysis.get("Digests"):
                    html += generate_digest_section(analysis["Digests"])
                
                if analysis.get("TrackingPixels"):
                    html += generate_tracking_section(analysis["TrackingPixels"])
                
                if analysis.get("Infrastructure"):
                    html += generate_infrastructure_section(analysis["Infrastructure"])
                
                if analysis.get("Auth"):
                    html += generate_authentication_section(analysis["Auth"])
            else:
                html += """
                    <div class="alert alert-warning">
                        <h4><i class="fa-solid fa-exclamation-triangle"></i> No Analysis Data</h4>
                        <p>No analysis data available for this email.</p>
                    </div>
                """
        
        html += "</section>\n"
    
    html += """
        </div>
        
        <!-- Back to top button -->
        <div class="fixed-bottom text-right p-3">
            <a href="#top" class="btn btn-primary btn-lg rounded-circle">
                <i class="fa-solid fa-arrow-up"></i>
            </a>
        </div>
        
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/js/bootstrap.min.js"></script>
        
        <script>
            // Smooth scrolling for anchor links
            $('a[href*="#"]').on('click', function (e) {
                e.preventDefault();
                $('html, body').animate({
                    scrollTop: $($(this).attr('href')).offset().top - 80
                }, 500, 'linear');
            });
        </script>
    """
    
    return html
