# PhaseSnare

**PhaseSnare** is a lightweight Python command-line tool for extracting and validating Indicators of Compromise (IOCs) from text files and security logs.

The name comes from the idea of a spider's snare: relevant indicators are caught from large amounts of otherwise unrelated log data.

The project is being developed incrementally as a practical exercise in Python, cybersecurity automation, log analysis, testing, and software engineering.

## Features

PhaseSnare currently supports:

* IPv4 address extraction
* IPv4 address validation
* Detection of malformed IPv4 candidates
* MD5 hash extraction
* SHA-1 hash extraction
* SHA-256 hash extraction
* CVE identifier extraction
* CVE normalization
* URL extraction
* URL validation
* E-mail address extraction
* Domain extraction
* Plain-text output
* JSON output
* Remove duplicate IOCs option
* Command-line file input
* Automated tests with pytest

## Usage

Analyze a text or log file:

```bash
python phasesnare.py samples/suspicious.log
```

By default, PhaseSnare displays the results as human-readable text.

### JSON output

Use the `--format` option to produce structured JSON output:

```bash
python phasesnare.py samples/suspicious.log --format json
```

This makes PhaseSnare output easier to consume in scripts, pipelines, or other security tooling.

### Remove duplicates

Use the `--unique` option to produce unique only output:

```bash
python phasesnare.py samples/suspicious.log --unique
```

### Command-line help

```bash
python phasesnare.py --help
```

## Example

Given a log containing indicators such as:

```text
Connection from 192.168.1.45
MD5: 5d41402abc4b2a76b9719d911017c592
SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
Exploit targeting cve-2024-3094
```

PhaseSnare can produce structured JSON output:

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

PhaseSnare uses `pytest` for automated testing.

Run the full test suite from the project root:

```bash
python -m pytest
```

The current test suite covers:

* Valid and invalid IPv4 extraction
* IPv4 validation
* IPv6 address extraction
* IPv6 address validation
* Detection of malformed IPv6 candidates
* MD5 extraction
* SHA-1 extraction
* SHA-256 extraction
* URL extraction
* E-mail address extraction
* Domain extraction
* CVE normalization
* Combined content analysis
* IOC deduplication
* JSON serialization

## Requirements

* Python 3
* pytest, for running the automated tests

The PhaseSnare application itself currently depends only on modules from the Python standard library.

## Project Structure

```text
PhaseSnare/
├── phasesnare.py
├── samples/
│   └── suspicious.log
├── tests/
│   └── test_extractor.py
├── README.md
├── requirements.txt
└── .gitignore
```

## How It Works

PhaseSnare separates IOC extraction from input and output handling.

The general processing flow is:

```text
Log or text file
       |
       v
Content analysis
       |
       +-- IPv4 extraction and validation
       +-- IPv6 extraction and validation
       +-- MD5 extraction
       +-- SHA-1 extraction
       +-- SHA-256 extraction
       +-- CVE extraction and normalization
       +-- URL extraction and validation
       +-- E-mail address extraction
       +-- Domain extraction
       |
       v
Structured results
       |
       +-- IOC deduplicated output in any format
       |
       +-- Plain-text output
       |
       +-- JSON output
```

This separation allows new IOC extractors and output formats to be added without tightly coupling them to the command-line interface.

## Current Limitations

PhaseSnare currently performs primarily syntactic IOC extraction.

For example, a hexadecimal string matching the expected size of an MD5 or SHA hash can be identified as a hash candidate, but PhaseSnare does not determine whether the value is actually malicious.

Similarly, a syntactically valid IP address is not necessarily a malicious indicator.

Threat classification and enrichment are intentionally outside the current scope.

## Roadmap

Planned improvements include:

* CSV output
* Output file support
* Whitelisting
* Additional CLI options
* Improved test coverage
* Optional threat intelligence enrichment

Development is intentionally incremental, prioritizing readable code, validation, automated testing, and clear separation of responsibilities.

## Project Status

PhaseSnare is under active development.

The current version is focused on establishing a reliable IOC extraction core before adding enrichment, external integrations, or more complex analysis features.
