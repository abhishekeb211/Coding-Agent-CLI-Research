# Hardcoded secrets vulnerability example

# Vulnerable: hardcoded credentials
API_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_PASSWORD = "MySecretPassword123!"
JWT_SECRET = "super-secret-jwt-key-12345"

def connect_to_api():
    # Vulnerable: hardcoded API key
    return requests.get("https://api.example.com", headers={"Authorization": f"Bearer {API_KEY}"})

def connect_to_database():
    # Vulnerable: hardcoded password
    return psycopg2.connect(
        host="localhost",
        database="mydb",
        user="admin",
        password=DATABASE_PASSWORD
    )
