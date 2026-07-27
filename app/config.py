import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")

    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")