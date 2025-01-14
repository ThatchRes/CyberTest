import os
import subprocess

# Vulnerability 1: SQL Injection
def vulnerable_query(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    # This query is vulnerable to SQL injection because it concatenates user input directly
    print(query)

# Vulnerability 2: Insecure use of eval()
def vulnerable_eval(user_input):
    result = eval(user_input)  # Dangerous, user input can execute arbitrary code
    print(result)

# Vulnerability 3: Hardcoded credentials
def vulnerable_credentials():
    username = "admin"  # Hardcoded username (Bad practice)
    password = "password123"  # Hardcoded password (Bad practice)
    print(f"Username: {username}, Password: {password}")

# Vulnerability 4: Insecure file operations
def insecure_file_operations(filename):
    # Opening a file without proper validation or sanitization
    with open(filename, 'r') as file:
        content = file.read()
    print(content)

# Vulnerability 5: Weak hash function for password storage
import hashlib
def weak_hash(password):
    # Using MD5 for hashing passwords (known to be insecure)
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    print(f"Hashed password (MD5): {hashed_password}")

# Vulnerability 6: Insecure HTTPS connection (not verifying SSL certificates)
import requests
def insecure_https_request():
    response = requests.get("https://example.com", verify=False)  # This bypasses SSL certificate validation
    print(response.text)

# Vulnerability 7: Insecure deserialization
import pickle
def insecure_deserialization():
    # Loading data from an untrusted source (pickle is unsafe)
    with open("user_data.pkl", "rb") as f:
        user_data = pickle.load(f)  # This could execute arbitrary code
    print(user_data)

# Vulnerability 8: Command injection
def command_injection(user_input):
    # Dangerous: user input directly in shell command
    subprocess.run(f"ls {user_input}", shell=True)

if __name__ == "__main__":
    # Example of calling vulnerable functions
    vulnerable_query("admin' OR '1'='1")
    vulnerable_eval("__import__('os').system('echo Hacked')")
    vulnerable_credentials()
    insecure_file_operations("/etc/passwd")
    weak_hash("mysecretpassword")
    insecure_https_request()
    insecure_deserialization()
    command_injection("; rm -rf /")
