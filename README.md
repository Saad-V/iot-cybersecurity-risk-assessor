# IoT Cybersecurity Risk & Compliance Assessor

A Python-based cybersecurity assessment tool that evaluates IoT device configurations, identifies security weaknesses, calculates risk scores, maps findings to the NIST Cybersecurity Framework 2.0, and generates an AI-assisted security assessment report in DOCX format.

## Overview

IoT devices often contain configuration weaknesses such as missing authentication, lack of encryption, insufficient logging, missing backups, and outdated firmware.

This project provides a small, practical assessment workflow that:

1. Reads IoT device configuration data from a CSV file.
2. Checks each device against predefined security requirements.
3. Calculates likelihood, impact, and risk scores.
4. Assigns severity levels to identified findings.
5. Maps findings to relevant NIST CSF 2.0 categories.
6. Uses Google Gemini to generate explanatory report sections.
7. Validates the AI-generated JSON response.
8. Produces a structured DOCX security assessment report.

The Python assessment engine remains the source of truth for all factual assessment results. Gemini is used only for narrative generation and explanation.

## Features

* CSV-based IoT asset assessment
* Configuration-based security checks
* Likelihood × impact risk scoring
* Low, Medium, High, and Critical severity classification
* Device-level finding summaries
* Overall assessment statistics
* NIST CSF 2.0 mapping
* Google Gemini integration for report narratives
* Structured JSON output
* DOCX report generation
* Validation of AI-generated report sections and device IDs

## Assessment Checks

The current version checks for:

| Configuration  | Condition  | Security Concern                                  |
| -------------- | ---------- | ------------------------------------------------- |
| Authentication | `no`       | Missing device or service authentication          |
| Encryption     | `no`       | Missing protection for device communications      |
| Logging        | `no`       | Missing security monitoring information           |
| Backup         | `no`       | Lack of recoverable data or configuration backups |
| Firmware       | `outdated` | Increased exposure due to outdated software       |

These checks are intentionally simple and are designed for demonstration and learning purposes. They do not replace a full enterprise security assessment.

## Risk Calculation

The project uses the following simplified risk model:

```text
Risk Score = Likelihood × Impact
```

Each value is scored on a scale from 1 to 5.

| Risk Score | Severity |
| ---------: | -------- |
|        1–5 | Low      |
|       6–10 | Medium   |
|      11–15 | High     |
|      16–25 | Critical |

The likelihood and impact values are project-defined assessment inputs and should be calibrated for a real organizational environment.

## NIST CSF 2.0 Mapping

The project maps findings to selected NIST Cybersecurity Framework 2.0 categories, including:

* `PR.AA-03` — Authentication of users, services, and hardware
* `PR.DS-02` — Protection of data in transit
* `PR.PS-02` — Software maintenance and replacement
* `PR.PS-04` — Logging and monitoring support
* `PR.DS-11` — Backup protection, maintenance, and testing

The mappings provide contextual guidance rather than claiming formal compliance or certification.

## Project Workflow

```text
devices.csv
    |
    v
CSV Parsing
    |
    v
Security Configuration Checks
    |
    v
Risk and Severity Calculation
    |
    v
NIST CSF Mapping
    |
    v
Structured Assessment JSON
    |
    v
Gemini Narrative Generation
    |
    v
JSON Validation
    |
    v
DOCX Report
```

## Example Assessment Results

For the included sample dataset:

| Metric                | Result |
| --------------------- | -----: |
| Devices assessed      |      8 |
| Devices with findings |      6 |
| Total findings        |     17 |
| Critical findings     |     12 |
| High findings         |      3 |
| Medium findings       |      2 |
| Low findings          |      0 |

These results are based on the included sample CSV data and are not representative of a real production environment.

## Technologies Used

* Python
* CSV module
* JSON
* `collections.defaultdict`
* Google Gemini API
* `google-genai`
* `python-docx`
* NIST Cybersecurity Framework 2.0

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/iot-cybersecurity-risk-assessor.git
cd iot-cybersecurity-risk-assessor
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

Activate it on Linux/macOS:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Gemini API Configuration

Create a `.env` file or configure the environment variable directly.

Example:

```env
GEMINI_API_KEY=your_api_key_here
```

Never commit your real API key to GitHub.

The `.env.example` file is included only as a configuration template.

## Running the Project

From the repository root:

```bash
python src/main.py
```

The program generates:

```text
outputs/assessment.json
outputs/report_content.json
outputs/iot_security_assessment_report.docx
```

## Input Format

The input file is located at:

```text
data/devices.csv
```

Example structure:

```csv
device_id,device_type,authentication,encryption,logging,backup,firmware
DEV001,Temperature Sensor,no,no,no,no,outdated
DEV002,Smart Gateway,yes,yes,yes,yes,current
```

The CSV can be extended with additional devices, provided the required columns remain available.

## Output Files

### `assessment.json`

Contains the factual assessment results generated by Python, including:

* Overall statistics
* Device summaries
* Individual findings
* Risk scores
* Severity levels
* NIST mappings
* Recommendations

### `report_content.json`

Contains the narrative sections generated by Gemini after validation.

### `iot_security_assessment_report.docx`

Contains the final human-readable assessment report with:

* Executive summary
* Overall assessment
* Risk overview
* Device-level findings
* NIST CSF mapping
* Recommended remediation
* Conclusion

## Design Principle

The project deliberately separates deterministic assessment logic from AI-generated explanation.

```text
Python:
- Reads data
- Performs checks
- Calculates risk
- Determines severity
- Defines findings
- Defines NIST mappings

Gemini:
- Explains the results
- Generates narrative sections
- Organizes report language
- Provides general cybersecurity context
```

This prevents the language model from changing factual risk scores, device counts, severity values, or assessment findings.

## Limitations

This is an educational proof-of-concept and has several limitations:

* Uses a simplified configuration-based assessment model
* Does not perform active network scanning
* Does not verify whether controls are actually implemented
* Does not inspect firmware binaries
* Does not identify CVEs automatically
* Does not test exploitability
* Does not provide formal compliance certification
* Uses project-defined likelihood and impact values
* Depends on the quality of the supplied CSV data

## Future Improvements

Possible future enhancements include:

* YAML or database-based configuration
* Custom risk scoring profiles
* Additional IoT security checks
* CVE and vulnerability database integration
* Evidence collection and attachments
* Interactive dashboard
* PDF report export
* Automated remediation tracking
* Role-based access control
* Historical assessment comparison

## Disclaimer

This tool is intended for educational, demonstration, and internal assessment workflow purposes. It should not be treated as a replacement for a professional penetration test, formal audit, compliance certification, or comprehensive enterprise risk assessment.

## Author

**V. Muhammed Saad Sabeel**

Engineering Student | Cybersecurity | IoT Security | Risk Assessment
