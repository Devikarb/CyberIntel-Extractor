# CyberIntel&Extractor

## Description:
This Python script is a comprehensive tool designed to perform various cybersecurity-related tasks, such as querying information about domains, IP addresses, and file hashes using multiple threat intelligence APIs. The script also includes functionality to extract relevant data (like domains, IPs, and hashes) from text input by leveraging Google's Gemini, making it a versatile tool for security analysts.A toolto make cybersecurity analysis more efficient, enabling faster response times and better threat detection.

## Key Features:

- Gemini AI-Powered Extraction: Automatically extracts domains, IP addresses, and file hashes from unstructured text.
- AbuseIPDB Integration: Evaluates the reputation of IP addresses to identify potentially malicious entities, complete with detection confidence.
- WHOIS Information Retrieval: Gathers comprehensive WHOIS data for domains and IP addresses, including registrar details and registration dates.
- URLScan Analysis: Queries URLScan for domain analysis and screenshots to assess website behavior and security.
- AlienVault Threat Intelligence: Enriches threat data with insights from AlienVault OTX, providing additional context to domain-related threats.

## How to Use:

- Set Up: Replace with your actual API keys for AbuseIPDB, VirusTotal, AlienVault OTX, and URLScan in the script.
- Run: Execute the script, choose the operation mode (domain, IP, hash, or generate), and input the relevant data.
- Analyze: Receive detailed, formatted reports for each domain, IP, or hash, highlighting key threat indicators and potential risks.

## Use Cases:

- Security Operations: Ideal for SOC teams needing to quickly verify the legitimacy of domains, IPs, or hashes during incident investigations.
- Threat Hunting: Useful for threat hunters conducting proactive searches for malicious entities across the web.

## Output:

Do you want to check a domain, IP, hash, or generate? Type 'domain', 'ip', 'hash', or 'generate' (or 'exit' to quit): generate

Enter the text for extraction (or type 'exit' to quit): 
"/n lets give some random domain example.com  random IP 198.51.100.150 and random hash 8f14e45fceea167a5a36dedd4bea2543," 
#Text given for extraction 

Extracted Data:

Hashes: 8f14e45fceea167a5a36dedd4bea2543
IPs: 198.51.100.150
Domains: example.com

### Results:
============================================================

---- Hashes ----

1. Hash: 8f14e45fceea167a5a36dedd4bea2543

- VirusTotal:

Harmless Votes: 0
Malicious Votes: 0
Suspicious Votes: 0
Undetected Votes: 65
Categories: 
Reputation: 29

- AlienVault OTX:

No pulses available

- MalShare: No data available or error occurred

____________________________________________________________


 ---- IPs: ---- 
 
1. IP: 198.51.100.150

- ABUSE IP (Detection: Not Malicious):

This IP was reported 0 times.
Confidence of Abuse: 0%
ISP: Test Net
Usage Type: Reserved
Hostname(s): 
Domain Name: None
Country: None
City: N/A

- VirusTotal:

Harmless Votes: 0
Malicious Votes: 0
Suspicious Votes: 0
Undetected Votes: 94
Categories: 
Reputation: 0

- WHOIS Information:

Domain: N/A
Registrar: N/A
Registered On: N/A
Expires On: N/A
Updated On: N/A

____________________________________________________________


 ---- Domains: ---- 
 
1. Domain: example.com

- ABUSE IP (Detection: Malicious):

This IP was reported 1 times.
Confidence of Abuse: 2%
ISP: EdgeCast NetBlk
Usage Type: Content Delivery Network
Hostname(s): 
Domain Name: edgecast.com
Country: BE
City: N/A

- WHOIS Information:

Domain: EXAMPLE.COM
Registrar: RESERVED-Internet Assigned Numbers Authority
Registered On: 1995-08-14 04:00:00
Expires On: 2025-08-13 04:00:00
Updated On: 2024-08-14 07:01:34

- VirusTotal:

Harmless Votes: 66
Malicious Votes: 0
Suspicious Votes: 1
Undetected Votes: 27
Categories: 
Reputation: 1

- AlienVault OTX:

Pulse Count: 50
Most Recent Pulse Description: This page stores Microsoft phishing page IOCs. Legitimate website for the brand is https://microsoft.com
NOLA defense is tracking newly observed phishing websites. Follow us on twitter https://twitter.com/noladefense
Top Tags: urls, phishing, scam

- URLScan:

![URLScan Screenshot](https://urlscan.io/screenshots/90776ae5-832f-4f63-80c0-dd2ef609674a.png)
