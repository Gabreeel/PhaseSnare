# PhaseSnare

**PhaseSnare** is a lightweight Python command-line tool for extracting, validating, normalizing, and organizing Indicators of Compromise (IOCs) from text files and security logs.

The project started as a practical exercise to refresh Python skills while building something useful for cybersecurity analysis. It is now evolving into a reusable IOC extraction component that can also support malware-analysis and experimental research workflows.

The name comes from the idea of a spider's snare: relevant indicators are caught from large amounts of otherwise unrelated text and log data.

---

## Features

PhaseSnare currently supports:

### IOC extraction

- IPv4 address extraction and validation
- IPv6 address extraction and validation
- Detection of malformed IP candidates
- MD5 hash extraction
- SHA-1 hash extraction
- SHA-256 hash extraction
- CVE identifier extraction and normalization
- HTTP/HTTPS URL extraction and validation
- E-mail address extraction
- Domain and subdomain extraction

### Output and processing

- Human-readable plain-text output
- JSON output
- Duplicate removal with `--unique`
- Preservation of indicator order when deduplicating
- Command-line file input

### Development quality

- Automated testing with `pytest`
- Individual extractor tests
- Combined content-analysis tests
- Validation and false-positive handling for selected IOC types
- Separation between extraction, analysis, formatting, and CLI behavior

---

## Usage

Analyze a text or log file:

```bash
python phasesnare.py samples/suspicious.log
```

By default, PhaseSnare prints a human-readable report.

### JSON output

Use `--format` or `-f`:

```bash
python phasesnare.py samples/suspicious.log --format json
```

or:

```bash
python phasesnare.py samples/suspicious.log -f json
```

### Remove duplicates

Use `--unique` or `-u`:

```bash
python phasesnare.py samples/suspicious.log --unique
```

Options can be combined:

```bash
python phasesnare.py samples/suspicious.log --format json --unique
```

### Command-line help

```bash
python phasesnare.py --help
```

---

## Example

Given content such as:

```text
Connection from 192.0.2.10
Connection from 192.0.2.10
Exploit targeting cve-2024-3094
Request to https://example.com/login
Suspicious sender analyst@example.com
SHA256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

PhaseSnare can produce structured JSON such as:

```json
{
    "ipv4": [
        "192.0.2.10"
    ],
    "ipv4_falsos_candidatos": [],
    "ipv6": [],
    "ipv6_falsos_candidatos": [],
    "md5": [],
    "sha256": [
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    ],
    "sha1": [],
    "cves": [
        "CVE-2024-3094"
    ],
    "urls": [
        "https://example.com/login"
    ],
    "urls_falsos_candidatos": [],
    "emails": [
        "analyst@example.com"
    ],
    "dominios": [
        "example.com"
    ]
}
```

With `--unique`, repeated values are removed while preserving the order of their first occurrence.

---

## How It Works

PhaseSnare separates extraction logic from command-line and output responsibilities.

```text
Input file
   |
   v
Read content
   |
   v
analisar_conteudo()
   |
   +-- IPv4 extraction and validation
   +-- IPv6 extraction and validation
   +-- MD5 extraction
   +-- SHA-1 extraction
   +-- SHA-256 extraction
   +-- CVE extraction and normalization
   +-- URL extraction and validation
   +-- E-mail extraction
   +-- Domain extraction
   |
   v
Structured results
   |
   +-- optional deduplication (--unique)
   |
   v
Output formatting
   |
   +-- TXT
   +-- JSON
```

The extractors are intentionally kept independent from file reading and presentation logic.

This makes it possible to reuse the IOC-analysis layer later in scripts, pipelines, tests, or research tooling without depending on the CLI.

---

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

The project currently remains intentionally small and primarily contained in a single Python module.

Splitting the code into packages or multiple modules will only be considered when the complexity of the project justifies it.

---

## Testing

PhaseSnare uses `pytest`.

Run the complete test suite from the repository root:

```bash
python -m pytest
```

The current suite covers:

- valid and invalid IPv4 extraction
- IPv4 semantic validation
- valid and invalid IPv6 extraction
- IPv6 semantic validation
- MD5 extraction
- SHA-1 extraction
- SHA-256 extraction
- CVE normalization
- URL extraction and validation
- unsupported/defanged URL behavior
- e-mail extraction
- malformed e-mail cases
- domain extraction
- malformed-domain false positives
- preservation of subdomains
- combined content analysis
- JSON serialization
- IOC deduplication
- preservation of order during deduplication

---

## Synthetic Sample Log

`samples/suspicious.log` is a synthetic long-term testing fixture.

It intentionally contains:

- valid indicators
- malformed candidates
- duplicate indicators
- private, loopback, and reserved addresses
- URLs
- domains
- e-mail addresses
- hashes
- CVEs
- JSON-formatted log lines
- Apache/SSH-style log entries
- unrelated noise

The file is intended to evolve with the project and support manual testing, regression checks, and future integration tests.

---

## Current Limitations

PhaseSnare currently performs primarily **syntactic extraction and structural validation**.

Finding an IOC-shaped value does not mean that the value is malicious.

For example:

- a syntactically valid IP address may be benign;
- a hexadecimal value matching SHA-256 length may not correspond to malicious content;
- a valid domain may be legitimate;
- PhaseSnare currently does not perform reputation or threat-intelligence lookups.

Some artifact formats are also intentionally unsupported for now, including defanged IOCs such as:

```text
hxxp://example[.]com
```

Support for those formats may be added explicitly in future versions.

---

## Research Direction

PhaseSnare is also being prepared for use as an IOC-normalization component in malware-analysis experiments.

A potential workflow is:

```text
malware sample
     |
     v
static-analysis output
     |
     v
PhaseSnare
     |
     v
structured IOC results
```

For experiments involving multiple versions or states of a sample, PhaseSnare can eventually help produce comparable structured results, for example:

```text
packed sample
    |
static analysis
    |
PhaseSnare
    |
packed_iocs.json


unpacked sample
    |
static analysis
    |
PhaseSnare
    |
unpacked_iocs.json
```

This direction may introduce additional artifact types and output features in future versions.

---

## Roadmap

### Near-term

- Output to file with `--output`
- CSV output
- Additional CLI options
- Improved integration tests
- Better handling of punctuation and edge cases in extracted values

### Malware-analysis / research support

- Windows path extraction
- UNC path extraction
- Windows Registry key extraction
- Defanged IOC normalization
- Structured sample metadata
- Packed/unpacked result comparison
- Export formats suitable for experimental datasets

### Longer-term

- Whitelisting
- IOC filtering by type
- Threat-intelligence enrichment
- Optional reputation lookups
- Better separation into modules if project complexity requires it

---

## Design Principles

Development is intentionally incremental.

The project currently prioritizes:

1. readable Python
2. predictable extractor behavior
3. low dependency count
4. automated testing
5. clear separation of responsibilities
6. reproducible output
7. usefulness in practical cybersecurity workflows

New complexity should only be introduced when it solves a real problem.

---

## Requirements

- Python 3
- `pytest` for development and testing

The PhaseSnare application itself currently relies only on Python's standard library.

---

## Project Status

PhaseSnare is under active development.

The core IOC extraction layer is functional. Current development is moving from adding basic IOC types toward improving CLI usability, reproducible output, and support for malware-analysis research workflows.