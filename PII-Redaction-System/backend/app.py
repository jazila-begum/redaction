from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os

from models import db, User, SystemRedactionRule
from auth import hash_password
from pii_redaction_service import PIIRedactionService
from routes import init_routes

load_dotenv()

def create_app():
    app = Flask(__name__)
    
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')
    app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/uploads')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    db.init_app(app)
    jwt = JWTManager(app)
    CORS(app)
    
    model_path = os.getenv('MODEL_PATH', 'best.pt')
    pii_service = PIIRedactionService(model_path)
    
    init_routes(app, pii_service)
    
    return app

def init_database(app):
    with app.app_context():
        db.create_all()
        
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                password_hash=hash_password('admin123'),
                role='Admin'
            )
            db.session.add(admin)
        
        default_rules = ['Name', 'Aadhaar Number', 'Phone Number', 'Date of Birth', 'Father Name', 'Address']
        
        for rule_name in default_rules:
            rule = SystemRedactionRule.query.filter_by(field_name=rule_name).first()
            if not rule:
                rule = SystemRedactionRule(
                    field_name=rule_name,
                    is_redacted=True,
                    redaction_template='Default'
                )
                db.session.add(rule)
        
        db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    app = create_app()
    init_database(app)
    
    print("Starting PII Redaction System...")
    print("Admin credentials: username='admin', password='admin123'")
    app.run(debug=True, host='0.0.0.0', port=5000)
