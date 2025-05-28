import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_secret")
    SQLALCHEMY_DATABASE_URI = 'postgresql://etamrakar:1tamrakar1@localhost/phishing_tool'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
