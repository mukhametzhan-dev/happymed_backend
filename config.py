# config.py
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
class Config:
    SECRET_KEY = 'secret_key'  # Replace with your actual secret key
    # SQLALCHEMY_DATABASE_URI = 'sqlite:///patients.db' previous sqlite 
    # SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqldb://root:password@localhost/happy_db'

    SMTP2GO_API_KEY = 'api-8B5895FA7DB14690B762617532289AA5'  # Replace with your actual SMTP2GO API key
    SMTP2GO_SENDER = '200107052@stu.sdu.edu.kz'  # Replace with your verified sender email
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB limit
