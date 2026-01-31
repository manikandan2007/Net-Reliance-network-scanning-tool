import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, render_template, request
from network_modules.pings import ping_host
from network_modules.scanning import scan_ports
from network_modules.dns_lookup import dns_lookup
from network_modules.tracer_route import traceroute
from network_modules.risk_score import calculate_risk
from network_modules.ssl_check import ssl_info
from network_modules.http_headers import get_headers
from network_modules.banner_grab import banner_grab

template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
app = Flask(__name__, template_folder=template_dir)

explanations = {
    'connectivity': {
        'title': 'Connectivity Test (Ping)',
        'content': '''
        <h2>What is Ping?</h2>
        <p>Ping is a fundamental network diagnostic tool that tests the reachability of a host on an IP network. It works by sending Internet Control Message Protocol (ICMP) echo request packets to the target and waiting for echo reply packets.</p>
        
        <h2>Why is it Important?</h2>
        <ul>
        <li><strong>Reachability Testing:</strong> Determines if a target host is online and accessible</li>
        <li><strong>Latency Measurement:</strong> Measures round-trip time (RTT) for packets</li>
        <li><strong>Packet Loss Detection:</strong> Identifies network congestion or connectivity issues</li>
        <li><strong>Troubleshooting:</strong> First step in diagnosing network problems</li>
        </ul>
        
        <h2>How it Works for Beginners</h2>
        <p>Imagine you're trying to call a friend. Ping is like dialing their number and waiting for them to pick up. If they answer quickly, the connection is good. If it takes time or doesn't connect, there might be network issues.</p>
        
        <div class="code-example">
        Example Ping Command:
        ping google.com
        
        Output shows:
        - Reply from [IP]: bytes=32 time=10ms TTL=118
        - Packet loss percentage
        - Round trip times (min/avg/max)
        </div>
        
        <h2>Security Considerations</h2>
        <p>While ping is generally safe, some networks block ICMP traffic for security reasons. Firewalls might filter ping requests to prevent reconnaissance attacks.</p>
        '''
    },
    'dns': {
        'title': 'DNS Resolution',
        'content': '''
        <h2>What is DNS?</h2>
        <p>DNS (Domain Name System) is the internet's phone book. It translates human-readable domain names (like www.google.com) into IP addresses that computers use to communicate.</p>
        
        <h2>Why DNS Matters</h2>
        <ul>
        <li><strong>Name Resolution:</strong> Converts domain names to IP addresses</li>
        <li><strong>Load Balancing:</strong> Distributes traffic across multiple servers</li>
        <li><strong>Redundancy:</strong> Provides backup servers if primary fails</li>
        <li><strong>Caching:</strong> Speeds up repeated requests</li>
        </ul>
        
        <h2>DNS Resolution Process</h2>
        <ol>
        <li>Browser checks local DNS cache</li>
        <li>Queries local DNS resolver (usually ISP)</li>
        <li>Resolver queries root servers</li>
        <li>Follows hierarchy: .com TLD → authoritative server</li>
        <li>Returns IP address to browser</li>
        </ol>
        
        <div class="code-example">
        Example DNS Lookup:
        nslookup google.com
        
        Output: google.com → 142.250.190.78
        </div>
        
        <h2>Security Implications</h2>
        <p>DNS can be vulnerable to spoofing attacks. DNSSEC provides authentication and integrity. Always verify SSL certificates match domain names.</p>
        '''
    },
    'ports': {
        'title': 'Port Analysis (Port Scanning)',
        'content': '''
        <h2>What are Network Ports?</h2>
        <p>Ports are virtual endpoints for network communications. Each service running on a computer listens on specific port numbers. There are 65,535 possible ports (0-65535).</p>
        
        <h2>Common Port Categories</h2>
        <ul>
        <li><strong>Well-known (0-1023):</strong> Reserved for standard services (HTTP:80, HTTPS:443)</li>
        <li><strong>Registered (1024-49151):</strong> Assigned by IANA for specific services</li>
        <li><strong>Dynamic/Private (49152-65535):</strong> Used for temporary connections</li>
        </ul>
        
        <h2>Port Scanning Explained</h2>
        <p>Port scanning systematically tests ports to determine which are open, closed, or filtered. Open ports indicate running services that can accept connections.</p>
        
        <div class="code-example">
        Port Scan Results:
        Port 80: Open (HTTP)
        Port 443: Open (HTTPS)  
        Port 22: Closed (SSH)
        Port 3389: Filtered (RDP)
        </div>
        
        <h2>Security Importance</h2>
        <ul>
        <li><strong>Vulnerability Assessment:</strong> Identifies exposed services</li>
        <li><strong>Service Discovery:</strong> Maps running applications</li>
        <li><strong>Risk Evaluation:</strong> Determines attack surface</li>
        <li><strong>Compliance:</strong> Ensures only necessary ports are open</li>
        </ul>
        
        <h2>Ethical Considerations</h2>
        <p>Port scanning can be seen as reconnaissance. Always obtain permission before scanning networks you don't own. Unauthorized scanning may violate laws.</p>
        '''
    },
    'risk': {
        'title': 'Security Risk Assessment',
        'content': '''
        <h2>What is Risk Assessment?</h2>
        <p>Risk assessment evaluates potential security threats based on open ports and running services. It assigns scores to identify systems that may be vulnerable to attacks.</p>
        
        <h2>Risk Scoring Methodology</h2>
        <ul>
        <li><strong>Port-based Scoring:</strong> Each open port has a risk weight</li>
        <li><strong>Service Analysis:</strong> Known vulnerable services increase risk</li>
        <li><strong>Exposure Level:</strong> Public-facing services score higher</li>
        <li><strong>Combination Effects:</strong> Multiple vulnerabilities compound risk</li>
        </ul>
        
        <h2>Risk Levels</h2>
        <ul>
        <li><strong>LOW (0-29):</strong> Minimal exposure, good security posture</li>
        <li><strong>MEDIUM (30-59):</strong> Some potential vulnerabilities, review recommended</li>
        <li><strong>HIGH (60+):</strong> Significant risks, immediate attention required</li>
        </ul>
        
        <div class="code-example">
        Risk Calculation Example:
        FTP (21): +20 points
        MySQL (3306): +40 points
        HTTP (80): +10 points
        Total Score: 70 → HIGH RISK
        </div>
        
        <h2>Why Risk Assessment Matters</h2>
        <p>Helps prioritize security efforts by identifying the most vulnerable systems. Enables proactive defense rather than reactive response to breaches.</p>
        
        <h2>Limitations</h2>
        <p>Risk scores are indicators, not definitive assessments. Actual vulnerability depends on service configuration, patches, and network controls.</p>
        '''
    },
    'trace': {
        'title': 'Network Trace (Traceroute)',
        'content': '''
        <h2>What is Traceroute?</h2>
        <p>Traceroute (tracert on Windows) maps the path packets take from source to destination, showing each intermediate router (hop) along the network path.</p>
        
        <h2>How Traceroute Works</h2>
        <ol>
        <li>Sends packets with increasing TTL (Time To Live) values</li>
        <li>Each router decrements TTL and discards expired packets</li>
        <li>Router sends ICMP "Time Exceeded" message back</li>
        <li>Records round-trip time for each hop</li>
        <li>Repeats with higher TTL until destination reached</li>
        </ol>
        
        <div class="code-example">
        Traceroute Output:
        1  192.168.1.1  1ms
        2  10.0.0.1     5ms  
        3  203.0.113.1  12ms
        4  google.com    15ms
        </div>
        
        <h2>Practical Applications</h2>
        <ul>
        <li><strong>Network Diagnostics:</strong> Identify routing problems</li>
        <li><strong>Performance Analysis:</strong> Find network bottlenecks</li>
        <li><strong>Topology Mapping:</strong> Understand network structure</li>
        <li><strong>ISP Issues:</strong> Detect problems with internet providers</li>
        </ul>
        
        <h2>Security Insights</h2>
        <p>Traceroute can reveal network architecture and potential security boundaries. Long paths or unusual routing may indicate network issues or security measures.</p>
        
        <h2>Limitations</h2>
        <p>Some routers don't respond to traceroute probes. Firewalls may block ICMP traffic. Results can vary based on network conditions and routing policies.</p>
        '''
    },
    'ssl': {
        'title': 'SSL/TLS Certificate Analysis',
        'content': '''
        <h2>What are SSL/TLS Certificates?</h2>
        <p>SSL (Secure Sockets Layer) and TLS (Transport Layer Security) certificates enable encrypted communication between browsers and servers, ensuring data privacy and server authenticity.</p>
        
        <h2>Certificate Components</h2>
        <ul>
        <li><strong>Subject:</strong> The domain or entity the certificate is issued to</li>
        <li><strong>Issuer:</strong> The Certificate Authority (CA) that issued it</li>
        <li><strong>Validity Period:</strong> Start and expiration dates</li>
        <li><strong>Public Key:</strong> Used for encryption</li>
        <li><strong>Signature:</strong> Digital signature from the CA</li>
        </ul>
        
        <h2>Why SSL Matters</h2>
        <ul>
        <li><strong>Encryption:</strong> Protects data in transit</li>
        <li><strong>Authentication:</strong> Verifies server identity</li>
        <li><strong>Integrity:</strong> Ensures data hasn't been tampered with</li>
        <li><strong>Trust:</strong> Builds user confidence in secure connections</li>
        </ul>
        
        <div class="code-example">
        Certificate Details:
        Subject: CN=www.google.com
        Issuer: CN=Google Internet Authority G3, O=Google Trust Services
        Valid from: Jan 1 2024
        Valid to: Mar 26 2024
        </div>
        
        <h2>Security Checks</h2>
        <ul>
        <li><strong>Expiration:</strong> Ensure certificate hasn't expired</li>
        <li><strong>Domain Match:</strong> Certificate must match domain name</li>
        <li><strong>Chain of Trust:</strong> Verify CA is trusted</li>
        <li><strong>Revocation:</strong> Check if certificate has been revoked</li>
        </ul>
        
        <h2>Common Issues</h2>
        <p>Expired certificates, self-signed certificates, domain mismatches, and revoked certificates can indicate security problems or misconfigurations.</p>
        '''
    },
    'headers': {
        'title': 'HTTP Response Headers',
        'content': '''
        <h2>What are HTTP Headers?</h2>
        <p>HTTP headers are key-value pairs sent between client and server with HTTP requests and responses. They provide metadata about the request/response, server configuration, and security policies.</p>
        
        <h2>Common Security Headers</h2>
        <ul>
        <li><strong>Content-Security-Policy:</strong> Prevents XSS attacks</li>
        <li><strong>X-Frame-Options:</strong> Prevents clickjacking</li>
        <li><strong>X-Content-Type-Options:</strong> Prevents MIME sniffing</li>
        <li><strong>Strict-Transport-Security:</strong> Enforces HTTPS</li>
        <li><strong>X-XSS-Protection:</strong> Enables XSS filtering</li>
        </ul>
        
        <h2>Server Information Headers</h2>
        <ul>
        <li><strong>Server:</strong> Reveals web server software and version</li>
        <li><strong>X-Powered-By:</strong> Shows backend technologies</li>
        <li><strong>Set-Cookie:</strong> Session and security cookie settings</li>
        <li><strong>Cache-Control:</strong> Caching directives</li>
        </ul>
        
        <div class="code-example">
        Example Headers:
        Server: nginx/1.18.0
        X-Frame-Options: DENY
        Content-Security-Policy: default-src 'self'
        Strict-Transport-Security: max-age=31536000
        </div>
        
        <h2>Security Analysis</h2>
        <ul>
        <li><strong>Missing Headers:</strong> Indicates lack of security measures</li>
        <li><strong>Outdated Software:</strong> Revealed by Server header</li>
        <li><strong>Cookie Security:</strong> Check for Secure and HttpOnly flags</li>
        <li><strong>CORS Policies:</strong> Review cross-origin access controls</li>
        </ul>
        
        <h2>Privacy Concerns</h2>
        <p>Headers can leak sensitive information about server configuration. Security headers help protect against common web vulnerabilities.</p>
        '''
    },
    'banner': {
        'title': 'Service Banner Grabbing',
        'content': '''
        <h2>What is Banner Grabbing?</h2>
        <p>Banner grabbing is a technique to identify the software and version running on open ports by connecting to the service and reading the initial response (banner) it sends.</p>
        
        <h2>How Banner Grabbing Works</h2>
        <ol>
        <li>Establish TCP connection to target port</li>
        <li>Send minimal data to trigger response</li>
        <li>Capture and analyze the service's greeting/banner</li>
        <li>Identify software type and version</li>
        </ol>
        
        <div class="code-example">
        HTTP Banner Example:
        HTTP/1.1 200 OK
        Server: Apache/2.4.41 (Ubuntu)
        Content-Type: text/html
        
        FTP Banner Example:
        220 ProFTPD 1.3.5a Server ready
        </div>
        
        <h2>Security Importance</h2>
        <ul>
        <li><strong>Version Detection:</strong> Identifies potentially vulnerable software</li>
        <li><strong>Service Inventory:</strong> Maps running applications</li>
        <li><strong>Vulnerability Research:</strong> Enables targeted security assessments</li>
        <li><strong>Compliance:</strong> Ensures approved software versions</li>
        </ul>
        
        <h2>Risks and Ethics</h2>
        <ul>
        <li><strong>Information Disclosure:</strong> Banners reveal system details</li>
        <li><strong>Reconnaissance:</strong> Helps attackers plan attacks</li>
        <li><strong>Legal Issues:</strong> May violate terms of service</li>
        <li><strong>Network Load:</strong> Can trigger security alerts</li>
        </ul>
        
        <h2>Defense Strategies</h2>
        <p>Configure services to minimize banner information. Use generic responses or disable unnecessary services. Keep software updated to reduce known vulnerabilities.</p>
        
        <h2>Limitations</h2>
        <p>Not all services provide banners. Some can be configured to hide version information. Results depend on service configuration and network filtering.</p>
        '''
    }
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    
    try:
        ping = ping_host(target)
        ip = dns_lookup(target)
        
        results, open_ports = scan_ports(target)
        ports_text = '\n'.join(results)
        
        score, level = calculate_risk(open_ports)
        
        trace_result = traceroute(target)
        
        ssl_result = ssl_info(target)
        if isinstance(ssl_result, dict) and 'Error' in ssl_result:
            ssl_text = ssl_result['Error']
        else:
            ssl_text = '\n'.join(f"{k}: {v}" for k, v in ssl_result.items())
        
        headers = get_headers(target)
        if isinstance(headers, dict) and 'Error' in headers:
            headers_text = headers['Error']
        else:
            headers_text = '\n'.join(f"{k}: {v}" for k, v in headers.items())
        
        banner = banner_grab(target, 80)
        
        return render_template('results.html', target=target, ping=ping, ip=ip, ports=ports_text, score=score, level=level, traceroute=trace_result, ssl_info=ssl_text, headers=headers_text, banner=banner)
    except Exception as e:
        return f"An error occurred: {str(e)}"

@app.route('/learn/<topic>')
def learn(topic):
    if topic in explanations:
        return render_template('learn.html', title=explanations[topic]['title'], content=explanations[topic]['content'])
    else:
        return "Topic not found", 404

if __name__ == '__main__':
    app.run(debug=True)