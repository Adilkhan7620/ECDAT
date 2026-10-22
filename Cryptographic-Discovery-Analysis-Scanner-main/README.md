 <div align="center">

# ECDAT
### Enterprise Cryptographic Discovery & Analysis Tool

**Discover cryptographic assets. Analyze security risks. Prepare for post-quantum migration.**

A cybersecurity project focused on discovering cryptographic assets, correlating security findings, and helping organizations prepare for Post-Quantum Cryptography (PQC) migration.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Project](https://img.shields.io/badge/Project-SIH%202026-purple)
![Status](https://img.shields.io/badge/Status-Under%20Development-orange)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity-red)

</div>

---

## 📌 Overview

Modern software systems use cryptographic algorithms, libraries, certificates, public and private keys, and other security-related components. However, these assets are often distributed across source code, dependencies, configuration files, and application infrastructure.

Without a centralized inventory, organizations may struggle to identify cryptographic weaknesses, assess their exposure, and prepare for the transition to quantum-resistant cryptography.

**ECDAT (Enterprise Cryptographic Discovery and Analysis Tool)** aims to address this challenge by combining findings from multiple security tools into a common analysis workflow.

The platform is designed to normalize findings, group related assets, correlate evidence, assess risks, and support the creation of a **Cryptographic Bill of Materials (CBOM)**.

> **Development status:** The project currently contains scanner orchestration interfaces, data models, and analysis components. Native execution of external scanners and parsing of their real outputs remain under development.

## 🎯 Objectives

- Discover cryptographic usage across software repositories.
- Identify security-relevant cryptographic evidence from multiple sources.
- Normalize and correlate findings into a common representation.
- Assess potential quantum-related risks and dependencies.
- Estimate the potential impact of affected cryptographic assets.
- Support Post-Quantum Cryptography migration planning.
- Work toward generating a structured Cryptographic Bill of Materials (CBOM).

## ✨ Key Features

### 🔍 Multi-Scanner Discovery

Designed to integrate multiple security tools to collect complementary evidence from source code, secrets, software dependencies, and cryptographic artifacts.

### 🧩 Finding Normalization

Converts scanner-specific findings into a common data representation to simplify analysis and comparison.

### 🔗 Asset Correlation

Groups related findings and helps identify potentially connected cryptographic assets.

### ⚠️ Risk Analysis

Includes analysis components intended to evaluate quantum-related risks, asset dependencies, and potential blast radius.

### 🔐 Post-Quantum Readiness

Aims to support prioritization and migration planning for cryptographic assets that may require attention as post-quantum standards are adopted.

### 📦 CBOM Direction

Designed toward a Cryptographic Bill of Materials that can provide a structured inventory of cryptographic assets and their supporting evidence.

*These are project goals and module capabilities, not a claim that every feature is production-ready.*

## 🏗️ System Architecture

```text
        Software Repository / Application
                      |
                      v
             CLI & Orchestrator
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       Semgrep     Gitleaks      Syft
          |           |           |
          +-----------+-----------+
                      |
              Trivy / OpenSSL
                      |
                      v
             Finding Normalization
                      |
                      v
              Asset Correlation
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
      Quantum     Blast Radius   Policy /
       Risk        Analysis     PQC Analysis
          |           |           |
          +-----------+-----------+
                      |
                      v
               Analysis Results
                      |
                      v
             JSON / Future CBOM
```

**Note:** This represents the intended architecture. The current scanner adapters are skeleton implementations and do not yet execute all external tools or parse their real outputs.

## 🛠️ Technology Stack

| Technology / Tool | Purpose |
|---|---|
| Python | Core implementation |
| Semgrep | Planned source-code security scanning |
| Gitleaks | Planned secret detection |
| Syft | Planned software-component inventory |
| Trivy | Planned dependency and vulnerability scanning |
| OpenSSL | Planned cryptographic artifact inspection |
| JSON | Structured findings and analysis output |
| unittest | Automated testing |

## 🔄 How It Works

1. **Target selection:** Specify a local repository or directory.
2. **Scanner orchestration:** Select the relevant scanner adapters.
3. **Evidence collection:** Gather findings once native scanner integrations are implemented.
4. **Normalization:** Convert findings into a common structure.
5. **Correlation:** Group related evidence and cryptographic assets.
6. **Risk analysis:** Apply available risk, policy, and migration analysis modules.
7. **Reporting:** Produce structured analysis results and work toward CBOM export.

## 📂 Project Structure

```text
ECDAT/
├── docs/
│   ├── ECDAT_Master_Hackathon_Guide.html
│   ├── Scanner_Discovery_Phase_Plan.md
│   └── sih_research.pdf
├── models/
├── scanner/
│   ├── core/
│   ├── models/
│   ├── scanners/
│   ├── orchestrator/
│   ├── normalizer/
│   ├── pipeline/
│   ├── policy/
│   ├── risk/
│   ├── output/
│   └── tests/
└── shared/
    ├── models/
    └── schemas/
```

| Directory | Responsibility |
|---|---|
| `scanner/core/` | Scanner base contracts |
| `scanner/models/` | Finding and analysis data models |
| `scanner/scanners/` | Scanner adapters |
| `scanner/orchestrator/` | Scanner selection and dispatch |
| `scanner/normalizer/` | Normalization and correlation |
| `scanner/pipeline/` | Analysis workflow |
| `scanner/policy/` | Compliance-related analysis |
| `scanner/risk/` | Risk and PQC analysis |
| `scanner/output/` | JSON output |
| `scanner/tests/` | Automated tests |
| `shared/` | Shared models and schemas |

## ⚙️ Installation and Setup

### Prerequisites

- Python 3.10 or later
- Git
- Windows, Linux, or macOS

### 1. Clone the repository

```bash
git clone https://github.com/Adilkhan7620/ECDAT.git
cd ECDAT
```

### 2. Check the command-line interface

Run the following command from the project root:

```bash
python -m scanner.main --help
```

### 3. Check scanner availability

```bash
python -m scanner.main doctor
```

This checks the availability of configured scanner executables. It does not perform a security scan.

### 4. Run the scan command

```bash
python -m scanner.main scan .
```

To select specific scanner adapters:

```bash
python -m scanner.main scan . --scanner semgrep --scanner openssl
```

### 5. Run the analysis pipeline

```bash
python -m scanner.main analyze .
```

Example with selected adapters:

```bash
python -m scanner.main analyze . --scanner gitleaks --scanner syft
```

**Important:** These commands exercise the current CLI and adapter workflow. Until native scanning and output parsing are implemented, the results must not be treated as a complete cryptographic inventory or security audit.

## 🧪 Testing

Run the test suite from the project root:

```bash
python -m unittest discover -s scanner/tests -v
```

The tests cover selected CLI, data-model, normalization, correlation, risk, policy, and scanner components. Passing tests does not establish that external scanner integrations are fully functional.

## 🚀 Development Roadmap

- [x] Establish CLI commands and scanner orchestration boundaries.
- [x] Add finding models and analysis components.
- [x] Add tests for selected pipeline modules.
- [ ] Implement native scanner execution.
- [ ] Parse and validate real scanner outputs.
- [ ] Improve cryptographic asset identification and correlation.
- [ ] Validate risk analysis against representative datasets.
- [ ] Implement and validate CBOM generation.
- [ ] Improve reports and end-to-end integration testing.
- [ ] Evaluate PQC recommendations against relevant standards.

## 🔒 Security and Responsible Use

- Scan only repositories and systems you own or have explicit permission to assess.
- Treat scan reports as potentially sensitive.
- Never commit credentials, private keys, tokens, or confidential scan results.
- Validate findings before making security or migration decisions.
- Do not treat missing findings as proof that a system is secure.
- ECDAT is an actively developed project and is not a substitute for a professional security assessment.

## 🤝 Contributing

Contributions, suggestions, and bug reports are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Implement your changes and add appropriate tests.
4. Run the test suite.
5. Submit a pull request describing your changes.

## 🎓 Project Information

**Project:** Enterprise Cryptographic Discovery and Analysis Tool (ECDAT)  
**Domain:** Cybersecurity and Post-Quantum Cryptography  
**Context:** Smart India Hackathon (SIH) 2026

## 📄 License

A license has not yet been specified in this repository. Until a license is added, permissions for reuse, modification, and redistribution are not explicitly granted.

---

<div align="center">

**ECDAT — Building toward cryptographic visibility and post-quantum readiness.**

</div>
