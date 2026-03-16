#!/usr/bin/env python3
"""
Test repository with intentional security vulnerabilities for testing
"""

import os
import subprocess

# CWE-798: Hardcoded Credentials
PASSWORD = "admin123"
API_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# CWE-89: SQL Injection
def get_user_by_id(user_id):
    """Vulnerable to SQL injection"""
    query = "SELECT * FROM users WHERE id = " + user_id
    return execute_query(query)

def search_users(username):
    """Another SQL injection vulnerability"""
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return execute_query(query)

# CWE-79: Cross-Site Scripting (XSS)
def render_user_profile(user_input):
    """Vulnerable to XSS"""
    html = "<html><body><h1>Welcome " + user_input + "</h1></body></html>"
    return html

# CWE-78: OS Command Injection
def ping_host(hostname):
    """Vulnerable to command injection"""
    command = "ping -c 1 " + hostname
    os.system(command)

def check_file(filename):
    """Another command injection"""
    subprocess.call("cat " + filename, shell=True)

# CWE-22: Path Traversal
def read_file(filename):
    """Vulnerable to path traversal"""
    with open("/var/www/uploads/" + filename, 'r') as f:
        return f.read()

# CWE-327: Weak Cryptography
import hashlib

def hash_password(password):
    """Using weak MD5 hash"""
    return hashlib.md5(password.encode()).hexdigest()

# CWE-502: Deserialization of Untrusted Data
import pickle

def load_user_data(data):
    """Vulnerable to pickle deserialization"""
    return pickle.loads(data)

# CWE-611: XML External Entity (XXE)
import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    """Vulnerable to XXE"""
    root = ET.fromstring(xml_string)
    return root

# CWE-326: Inadequate Encryption Strength
from Crypto.Cipher import DES

def encrypt_data(data, key):
    """Using weak DES encryption"""
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

# CWE-330: Use of Insufficiently Random Values
import random

def generate_session_token():
    """Using weak random number generator"""
    return str(random.randint(1000000, 9999999))

# CWE-601: Open Redirect
def redirect_user(url):
    """Vulnerable to open redirect"""
    return f"<meta http-equiv='refresh' content='0; url={url}'>"

# CWE-732: Incorrect Permission Assignment
def create_temp_file():
    """Creating file with insecure permissions"""
    filename = "/tmp/sensitive_data.txt"
    with open(filename, 'w') as f:
        f.write("sensitive data")
    os.chmod(filename, 0o777)  # World-writable

# Helper function (not vulnerable)
def execute_query(query):
    """Placeholder for database execution"""
    pass

if __name__ == "__main__":
    print("This file contains intentional vulnerabilities for testing purposes")
    print("DO NOT use this code in production!")
