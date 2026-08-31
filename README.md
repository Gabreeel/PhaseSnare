# IOC-Hunter

IOC-Hunter is a Python command-line tool for extracting Indicators of Compromise (IOCs) from text files and security logs.

The project is developed as a practical exercise in Python, cybersecurity automation, log analysis, testing, and software engineering practices.

## Current Features

IOC-Hunter currently supports:

* IPv4 address extraction and validation
* Detection of malformed IPv4 candidates
* MD5 hash extraction
* SHA-1 hash extraction
* SHA-256 hash extraction
* CVE identifier extraction
* CVE normalization
* Text output
* JSON output
* Command-line file input
* Automated tests with pytest

## Usage

Analyze a text or log file:

```bash
python iochunter.py samples/suspicious.log
```

The default output format is plain text.

JSON output is available with:

```bash
python iochunter.py samples/suspicious.log --format json
```

Command-line help:

```bash
python iochunter.py --help
```

## Example

Plain-text output:

```text
Resultados encontrados:

Endereço IPv4 válido: 192.168.1.45

Quantidade de endereços IPv4 válidos: 1

Hash MD5 encontrado: 5d41402abc4b2a76b9719d911017c592

Hash SHA-1 encontrado: da39a3ee5e6b4b0d3255bfef95601890afd80709

CVE encontrado: CVE-2024-3094
```

JSON output:

```json
{
    "ipv4": [
        "192.168.1.45"
    ],
    "ipv4_falsos_candidatos": [],
    "md5": [
        "5d41402abc4b2a76b9719d911017c592"
    ],
    "sha256": [],
    "sha1": [
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    ],
    "cves": [
        "CVE-2024-3094"
    ]
}
```

## Testing

The project uses `pytest` for automated testing.

Run the test suite from the project root:

```bash
python -m pytest
```

Tests currently cover individual IOC extractors, malformed inputs, CVE normalization, combined content analysis, and JSON serialization.

## Requirements

* Python 3
* pytest, for running the automated tests

The application itself currently uses only modules from the Python standard library.

## Project Structure

```text
ioc-hunter/
├── iochunter.py
├── samples/
│   └── suspicious.log
├── tests/
│   └── test_extractor.py
├── README.md
├── requirements.txt
└── .gitignore
```

The sample log contains valid indicators, malformed values, and unrelated data for testing extraction and validation behavior.

## Development Status

IOC-Hunter is under active development.

Planned improvements include:

* IPv6 extraction
* URL extraction
* Domain extraction
* E-mail address extraction
* Deduplication options
* CSV output
* Output file support
* Whitelisting
* Additional CLI options
* Optional threat intelligence integrations

Development is intentionally incremental, prioritizing readable code, validation, automated testing, and clear separation of responsibilities.
