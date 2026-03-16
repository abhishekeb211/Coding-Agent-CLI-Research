# Compliance Framework Policies

## OWASP Top 10 2021

```yaml
policies:
  - id: owasp-a01-broken-access
    name: A01 - Broken Access Control
    action: deny
    severity: high
    cwe:
      - CWE-22   # Path Traversal
      - CWE-284  # Access Control

  - id: owasp-a02-crypto-failures
    name: A02 - Cryptographic Failures
    action: deny
    severity: high
    cwe:
      - CWE-327  # Weak Crypto
      - CWE-326  # Inadequate Encryption

  - id: owasp-a03-injection
    name: A03 - Injection
    action: deny
    severity: critical
    cwe:
      - CWE-89   # SQL Injection
      - CWE-78   # Command Injection
      - CWE-79   # XSS

  - id: owasp-a05-security-misconfig
    name: A05 - Security Misconfiguration
    action: warn
    severity: medium
    cwe:
      - CWE-798  # Hardcoded Credentials

  - id: owasp-a08-integrity-failures
    name: A08 - Software and Data Integrity Failures
    action: deny
    severity: high
    cwe:
      - CWE-502  # Deserialization
```

## CWE Top 25

```yaml
policies:
  - id: cwe-top-25
    name: CWE Top 25 Most Dangerous
    action: deny
    severity: high
    cwe:
      - CWE-787  # Out-of-bounds Write
      - CWE-79   # XSS
      - CWE-89   # SQL Injection
      - CWE-20   # Improper Input Validation
      - CWE-78   # Command Injection
      - CWE-125  # Out-of-bounds Read
      - CWE-22   # Path Traversal
      - CWE-352  # CSRF
      - CWE-434  # Unrestricted Upload
      - CWE-862  # Missing Authorization
```

## PCI-DSS Compliance

```yaml
policies:
  - id: pci-dss-6-5-1-injection
    name: PCI-DSS 6.5.1 - Injection Flaws
    action: deny
    severity: critical
    cwe:
      - CWE-89
      - CWE-78

  - id: pci-dss-6-5-3-crypto
    name: PCI-DSS 6.5.3 - Insecure Cryptographic Storage
    action: deny
    severity: high
    cwe:
      - CWE-327
      - CWE-798

  - id: pci-dss-6-5-7-xss
    name: PCI-DSS 6.5.7 - Cross-site Scripting
    action: deny
    severity: high
    cwe:
      - CWE-79
```
