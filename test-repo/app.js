// Test JavaScript file with security vulnerabilities

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');

// CWE-798: Hardcoded Credentials
const DB_PASSWORD = 'password123';
const API_SECRET = 'my-secret-key-12345';

// CWE-89: SQL Injection
function getUserById(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return db.query(query);
}

// CWE-79: Cross-Site Scripting
function renderWelcome(username) {
    return "<h1>Welcome " + username + "</h1>";
}

// CWE-78: Command Injection
const { exec } = require('child_process');

function pingHost(host) {
    exec('ping -c 1 ' + host, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

// CWE-22: Path Traversal
const fs = require('fs');

function readUserFile(filename) {
    return fs.readFileSync('/uploads/' + filename, 'utf8');
}

// CWE-327: Weak Cryptography
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// CWE-502: Deserialization
function loadUserData(data) {
    return eval('(' + data + ')');  // Dangerous eval
}

// CWE-601: Open Redirect
function redirectUser(req, res) {
    const url = req.query.url;
    res.redirect(url);  // No validation
}

// CWE-330: Weak Random
function generateToken() {
    return Math.random().toString(36).substring(7);
}

// CWE-614: Sensitive Cookie Without Secure Flag
function setSessionCookie(res, sessionId) {
    res.cookie('session', sessionId, { httpOnly: false });
}

// CWE-918: Server-Side Request Forgery
const axios = require('axios');

async function fetchUrl(url) {
    return await axios.get(url);  // No validation
}

console.log('Test application with vulnerabilities');
