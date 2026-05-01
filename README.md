# Pallock - Advanced Zero-Day Vulnerability Scanner

Pallock is a powerful Python-based web vulnerability scanner that uses advanced techniques to detect zero-day vulnerabilities, security misconfigurations, and potential exploitation vectors.

## Features

- **Zero-Day Detection**: Advanced AI-powered detection using machine learning
- **Multiple Vulnerability Types**: XSS, SQLi, Command Injection, Path Traversal, Template Injection, etc.
- **Exploit Framework**: Automatic proof-of-concept generation and testing
- **Threat Intelligence**: Integration with VirusTotal, Shodan, and Censys
- **Advanced Crawling**: Intelligent web crawling with JavaScript analysis
- **Fuzzing Engine**: Comprehensive payload testing
- **Multiple Output Formats**: JSON, HTML, XML, and text reports
- **Modern Architecture**: Async/await for high performance

## Installation

```bash
# Clone the repository
git clone https://github.com/SayerLinux/Pallock.git
cd Pallock

# Install dependencies
pip install -r requirements.txt

# Set up environment variables (optional)
export SHODAN_API_KEY="your_shodan_key"
export VIRUSTOTAL_API_KEY="your_virustotal_key"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"
```

## Usage

### Basic Scan
```bash
python pallock.py -u https://example.com
```

### Deep Scan with Zero-Day Detection
```bash
python pallock.py -u https://example.com --deep-scan --zero-day-only
```

### Scan Multiple URLs from File
```bash
python pallock.py -f urls.txt --output report.html
```

### Advanced Options
```bash
python pallock.py -u https://example.com \
  --deep-scan \
  --threads 20 \
  --timeout 60 \
  --output report.json \
  --format json \
  --proxy http://proxy:8080
```

## Command Line Options

- `-u, --url`: Target URL to scan
- `-f, --file`: File containing URLs to scan
- `--deep-scan`: Enable deep scanning mode
- `--zero-day-only`: Scan only for zero-day vulnerabilities
- `--threads`: Number of threads to use (default: 10)
- `--timeout`: Request timeout in seconds (default: 30)
- `--user-agent`: Custom User-Agent string
- `--proxy`: Proxy URL (http://proxy:port)
- `--output`: Output file for results
- `--format`: Output format (json, html, xml, txt)
- `--verbose, -v`: Enable verbose output
- `--quiet, -q`: Quiet mode - minimal output

## Vulnerability Detection

Pallock can detect various types of vulnerabilities:

- **Zero-Day Vulnerabilities**: Using ML-based anomaly detection
- **Template Injection**: Freemarker, Velocity, Jinja2, Thymeleaf
- **Deserialization**: Java, PHP, Python deserialization
- **JNDI Injection**: Log4j and similar vulnerabilities
- **SQL Injection**: Various database systems
- **Cross-Site Scripting (XSS)**: Reflected and stored XSS
- **Command Injection**: OS command execution
- **Path Traversal**: Local file inclusion
- **LDAP Injection**: Directory service attacks
- **XXE**: XML External Entity attacks
- **SSRF**: Server-Side Request Forgery
- **NoSQL Injection**: MongoDB and other NoSQL databases

## Exploit Framework

Pallock includes an advanced exploit framework that:

- Generates proof-of-concept exploits automatically
- Tests exploits in safe mode
- Creates executable Python scripts
- Supports multiple vulnerability types
- Includes detailed documentation

## Threat Intelligence

Integration with leading threat intelligence platforms:

- **VirusTotal**: Domain reputation and malware detection
- **Shodan**: Internet-wide scanning and service detection
- **Censys**: Certificate and infrastructure analysis
- **WHOIS**: Domain registration information
- **DNS**: DNS record analysis and subdomain discovery

## Machine Learning

Pallock uses machine learning for:

- Zero-day vulnerability detection
- Anomaly-based threat detection
- Response pattern analysis
- Behavioral analysis
- Confidence scoring

## Output Formats

### JSON Report
```json
{
  "scan_id": "uuid",
  "scan_info": {
    "start_time": "2024-01-01T00:00:00",
    "end_time": "2024-01-01T00:10:00"
  },
  "statistics": {
    "total": 15,
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 3,
    "zero_days": 1
  },
  "findings": [
    {
      "type": "SQL Injection",
      "severity": "CRITICAL",
      "url": "https://example.com/search",
      "description": "SQL injection vulnerability found",
      "confidence": 0.95,
      "zero_day": false
    }
  ]
}
```

### HTML Report
Beautiful, interactive HTML reports with:
- Vulnerability summaries
- Detailed findings
- Risk assessments
- Exploit information
- Remediation suggestions

## Security Considerations

- Always obtain proper authorization before scanning
- Use the `--safe-exploits-only` flag for safe testing
- Respect rate limits and server resources
- Follow responsible disclosure for discovered vulnerabilities
- Keep the tool updated for latest detection capabilities

## API Keys (Optional)

For enhanced threat intelligence, obtain API keys from:

- [VirusTotal](https://www.virustotal.com/gui/join-us)
- [Shodan](https://account.shodan.io/register)
- [Censys](https://censys.io/account/register)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

**SayerLinux**
- Email: SayerLinux1@gmail.com
- GitHub: https://github.com/SayerLinux

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this tool.

## Version History

- **v1.0.0** (2024-01-01)
  - Initial release
  - Zero-day detection engine
  - Exploit framework
  - Threat intelligence integration
  - Multiple output formats