import os
import hashlib
import subprocess
import pickle

# Hardcoded secret key (Issue: Hardcoded Secrets)
SECRET_KEY = "12345"

# Insecure hash algorithm (Issue: Weak Hash Function)
def insecure_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

# Command injection vulnerability (Issue: Command Injection)
def delete_files(directory):
    os.system(f"rm -rf {directory}")

# Untrusted deserialization (Issue: Insecure Deserialization)
def load_user_data(data):
    return pickle.loads(data)

# SQL injection vulnerability (Issue: SQL Injection)
def fetch_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    print(f"Executing query: {query}")
    # Simulated database call
    return query

# Insecure random number generator (Issue: Weak Random Number Generation)
def generate_token():
    import random
    return random.randint(1000, 9999)

# Debugging feature left in production (Issue: Debug Code)
if __name__ == "__main__":
    print("DEBUG MODE: Running insecure script...")
    print("Generated hash:", insecure_hash("password123"))
    print("Random token:", generate_token())
    delete_files("/tmp/test_directory")
    print(fetch_user_data("1 OR 1=1"))
