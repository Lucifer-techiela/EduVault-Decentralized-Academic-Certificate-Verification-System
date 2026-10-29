const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'eduvault_lloyd_secret_key_2026';

// Cybersecurity Middleware: Helmet HTTP headers, CORS & Rate Limiting
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname)));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { status: 429, error: 'Too many requests. Rate limit exceeded.' }
});
app.use('/api/', apiLimiter);

// MongoDB Schema Definition
const Certificate = require('./models/Certificate');
const { requireRole } = require('./middleware/auth');

// Core SHA-256 Cryptographic Engine (Node.js native crypto module)
function computeCertificateHash({ credentialId, studentName, course, year }) {
  const normalizedCourse = course.trim().replace(/\s*[–—-]\s*/g, '-');
  const normalizedPayload = `${credentialId.trim()} | ${studentName.trim()} | ${normalizedCourse} | ${year.trim()}`;
  return crypto.createHash('sha256').update(normalizedPayload, 'utf8').digest('hex');
}

// 1. Admin Route: Issue Certificate & Generate SHA-256 Fingerprint
app.post('/api/certificates/issue', requireRole('admin', JWT_SECRET), async (req, res) => {
  try {
    const { credentialId, studentName, rollNo, course, year } = req.body;
    const hash = computeCertificateHash({ credentialId, studentName, course, year });

    const newCert = await Certificate.create({
      credentialId,
      studentName,
      rollNo,
      course,
      year,
      hash
    });

    res.status(201).json({ status: 'ISSUED', record: newCert, sha256: hash });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// 2. Public Verification Route: Verify by Credential ID or Recompute Hash
app.post('/api/certificates/verify', async (req, res) => {
  try {
    const { credentialId, studentName, course, year } = req.body;
    const cert = await Certificate.findOne({ credentialId: credentialId.trim().toUpperCase() });

    if (!cert) {
      return res.status(404).json({ status: 'NOT_FOUND', message: 'Credential ID not found' });
    }

    const candidateHash = computeCertificateHash({
      credentialId: cert.credentialId,
      studentName: studentName || cert.studentName,
      course: course || cert.course,
      year: year || cert.year
    });

    const isAuthentic = candidateHash === cert.hash;
    res.status(200).json({
      status: isAuthentic ? 'VALID' : 'TAMPERED',
      storedHash: cert.hash,
      computedHash: candidateHash,
      certificate: cert
    });
  } catch (error) {
    res.status(500).json({ error: 'Verification service error' });
  }
});

// Serve Frontend UI
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`EduVault Server running securely on http://localhost:${PORT}`);
});
