# EduVault: Decentralized Academic Certificate Verification System

**B.Tech Mini Project (BCC351) — Session 2026–27**  
**Institution:** Lloyd Institute of Engineering & Technology, Greater Noida (Affiliated to AKTU, Lucknow)  
**Department:** Computer Science & Engineering – AIML  
**Submitted By:** Akshay Nischal (Roll No: `2501531530023`, Sec E)  
**Project Guide:** Mr. Saroj (Assistant Professor, Dept. of CSE – AIML)

---

## Overview
EduVault is a secure, role-based academic certificate issuance and verification platform powered by **SHA-256 cryptographic hashing**, **Node.js**, **Express.js**, and **MongoDB**. Every issued credential receives a unique 256-bit digital fingerprint so any tampering is detected in real time.

## Key Features
1. **Administrator / Institution Portal**: Role-Based Access Control (RBAC) protected portal for university authorities to issue certificates and generate SHA-256 fingerprints.
2. **Student Portal**: Dedicated student dashboard to preview verified credentials and download official signed PDF certificates.
3. **Public Verification Portal**: Instant verification by **Credential ID** (`EDV-2026-0001`) or **Certificate File Upload** displaying `VALID` or `TAMPERED` status.
4. **Cybersecurity Hardening**: Helmet HTTP headers, XSS & NoSQL injection sanitization, JWT RBAC middleware, and API rate limiting.
