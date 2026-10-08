# PhaseSnare

PhaseSnare is a lightweight Python CLI for extracting IOC candidates from UTF-8 text files and security logs. It produces plain-text or JSON reports, optionally removes repeated values, and can save results to a file.

The project is developed as a practical Python learning exercise and is evolving toward a reusable component for malware-analysis research. Finding an indicator-shaped value does not establish that it is malicious.

## Current capabilities

- IPv4 and IPv6 candidate extraction with address validation using `ipaddress`.
- MD5, SHA-1 and SHA-256 pattern extraction.
- CVE identifier extraction and uppercase normalization.
- HTTP/HTTPS URL extraction with basic structural checks.
- E-mail, domain and subdomain extraction.
- TXT and JSON output.
- Exact-value deduplication with `--unique`, preserving first-occurrence order.
- File output with `--output`.
- Separate messages for input and output file errors, written to `stderr`.
- Exit codes for success and handled failures.
- Protection against writing output to the same resolved path as the input.

The application uses Python's standard library. `pytest` is needed for development tests.

## Getting started

Use Python 3 and run commands from the repository root. No application dependencies need to be installed.

```bash
python phasesnare.py samples/suspicious.log
```

The default format is a human-readable TXT report.

### CLI options

| Argument | Purpose |
| --- | --- |
| `log_file` | Path to the UTF-8 input file (required). |
| `-f`, `--format` | Output format: `txt` or `json`. Default: `txt`. |
| `-u`, `--unique` | Remove exact duplicates within each result category. |
| `-o`, `--output` | Write the report to a file instead of printing it. |
| `-h`, `--help` | Show command-line help. |

Print JSON:

```bash
python phasesnare.py samples/suspicious.log -f json
```

Print JSON with exact duplicates removed:

```bash
python phasesnare.py samples/suspicious.log -f json -u
```

Save JSON:

```bash
python phasesnare.py samples/suspicious.log -f json -u -o resultado.json
```

Save TXT:

```bash
python phasesnare.py samples/suspicious.log -o resultado.txt
```

### File output behavior

The destination's parent directory must already exist. An existing destination file is overwritten. The CLI rejects a destination whose resolved path matches the input path; this check does not cover every filesystem alias, such as hard links.

On successful file output, the CLI prints a confirmation to `stdout`. Without `--output`, the report itself is written to `stdout`.

Handled input/output errors and same-path rejection are reported to `stderr`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Processing completed successfully. |
| `1` | A handled file access error or same-path rejection occurred. |
| `2` | `argparse` rejected the command-line arguments. |

Exit codes communicate status to other programs independently of the printed message. Unexpected exceptions are not yet consistently handled; see the limitations below.

## Output and reuse

Results are a dictionary of lists with these keys:

```text
ipv4, ipv4_falsos_candidatos
ipv6, ipv6_falsos_candidatos
md5, sha1, sha256
cves
urls, urls_falsos_candidatos
emails
dominios
```

The `*_falsos_candidatos` lists contain extracted candidates rejected by the current checks. They are not a complete inventory of malformed values in the input.

The analysis function can also be imported without running the CLI:

```python
from phasesnare import analisar_conteudo, deduplicar_resultados

resultados = analisar_conteudo(
    "Connection from 192.0.2.10; reference cve-2024-3094"
)
resultados = deduplicar_resultados(resultados)

assert resultados["ipv4"] == ["192.0.2.10"]
assert resultados["cves"] == ["CVE-2024-3094"]
```

CVE values are normalized to uppercase. General canonicalization is not implemented: differently capitalized hashes and equivalent IPv6 spellings can remain distinct even with `--unique`. A domain found inside a URL or e-mail can also appear in the domain category.

## Architecture

```text
Read UTF-8 input
    -> analisar_conteudo(): call independent extractors
    -> optionally deduplicar_resultados()
    -> formatar_resultados_txt() or formatar_resultados_json()
    -> print report or write output file
```

Extractors operate on strings and do not read files, query reputation services, or execute samples. `main()` coordinates file access and presentation and returns a status code. The script entry point passes that code to `sys.exit()`.

The project currently fits in one module. Splitting responsibilities into separate modules is planned when comparison and evidence tracking justify it.

```text
PhaseSnare/
├── phasesnare.py
├── samples/
│   ├── suspicious.log
│   └── suspiciouslegacy.log
├── tests/
│   └── test_extractor.py
├── README.md
├── requirements.txt
└── .gitignore
```

## Development and tests

Install the test dependency into your development environment:

```bash
python -m pip install pytest
```

`requirements.txt` is currently empty; installing it does not install pytest.

Run the suite:

```bash
python -m pytest -q
```

Tests cover individual extractors, combined analysis, JSON/TXT formatting and deduplication. File-handling tests also cover JSON output, input preservation, missing input, invalid output destination, error messages and return codes from `main()`.

File-handling tests use pytest's `tmp_path` fixture for isolated inputs and outputs and `capsys` to inspect `stdout` and `stderr`. Testing `main()` directly does not by itself verify process-level exit codes.

`samples/suspicious.log` contains synthetic indicators, duplicates, malformed candidates and unrelated noise. It is useful for manual checks, but it is not an annotated accuracy benchmark.

## Known limitations

PhaseSnare is an extraction prototype, not a malware verdict engine.

- Extracted IPs, domains, URLs and hashes are not checked for maliciousness or reputation.
- Hash patterns establish hexadecimal length, not algorithm provenance or association with a file.
- CVE identifiers are matched by syntax; their existence is not verified.
- Domain extraction can misclassify filenames such as `powershell.exe` and dotted text such as `soc.team`.
- URL checks are basic. Trailing punctuation may be retained, uppercase schemes can be missed, and malformed bracketed hosts can raise an unhandled exception.
- Some IPv6 forms, including IPv4-embedded addresses, can be extracted partially.
- E-mail matching is heuristic and does not implement full standards validation.
- Defanged indicators such as `hxxp://example[.]com` are not supported.
- Input must be UTF-8 text. Decoding errors are not currently handled explicitly.
- The entire input and results are held in memory; size limits and streaming are not implemented.
- Results do not yet preserve source lines, positions or original-to-normalized mappings.
- Packed/unpacked comparison, binary string extraction and unpacking are not implemented.

## Research direction

The intended workflow consumes artifacts produced by other analysis tools:

```text
Packed/unpacked sample pair
    -> static-analysis tools
    -> text artifacts
    -> PhaseSnare extraction
    -> structured results
    -> comparison (planned)
```

The first comparison feature will report indicators common to both artifacts and indicators observed only in each one. It will compare observations, not prove that packing caused a difference.

An indicator absent from an artifact is not necessarily absent from the sample. Reproducible experiments must record sample identity, how each state was obtained, analysis-tool versions and parameters, and artifact hashes. Sample hashes must remain separate from hash-shaped values found in the text.

## Prioritized roadmap

1. **Reliability:** regression tests for malformed URLs and IPv6 boundaries, better encoding handling, and process-level CLI tests.
2. **Comparison:** minimal normalization and deterministic common/exclusive sets from two artifacts, preserving current CLI usage.
3. **Evidence and accuracy:** source tracking, versioned output schema, annotated fixtures, precision/recall measurements, and explicit defanged normalization.
4. **Research workflows:** Windows/UNC paths and Registry artifacts, paired-sample metadata, batch processing, and experimental tables/CSV.
5. **External use:** installation packaging, CI, a chosen license, and feedback from researchers and analysts using real workflows.

Possible future value lies in local, traceable comparison across sample states and analysis tools. A dashboard, online enrichment or commercial service will depend on demonstrated user needs rather than being prerequisites for the core tool.
