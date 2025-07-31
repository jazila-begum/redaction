from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Guest')  # Admin, Intern, Guest
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    permissions = db.relationship('UserPermission', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    uploaded_documents = db.relationship('Document', backref='uploader', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class UserPermission(db.Model):
    __tablename__ = 'user_permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    data_class = db.Column(db.String(50), nullable=False)  # Name, Aadhaar, Phone, etc.
    can_view = db.Column(db.Boolean, default=False)
    can_reveal = db.Column(db.Boolean, default=False)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'data_class'),)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'data_class': self.data_class,
            'can_view': self.can_view,
            'can_reveal': self.can_reveal
        }

class SystemRedactionRule(db.Model):
    __tablename__ = 'system_redaction_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    field_name = db.Column(db.String(50), unique=True, nullable=False)
    is_redacted = db.Column(db.Boolean, default=True)
    custom_regex = db.Column(db.Text)
    redaction_template = db.Column(db.String(50), default='Default')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'field_name': self.field_name,
            'is_redacted': self.is_redacted,
            'custom_regex': self.custom_regex,
            'redaction_template': self.redaction_template,
            'updated_at': self.updated_at.isoformat()
        }

class Document(db.Model):
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    original_storage_path = db.Column(db.String(500), nullable=False)
    redacted_storage_path = db.Column(db.String(500))
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    redacted_fields = db.relationship('RedactedField', backref='document', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'original_filename': self.original_filename,
            'uploaded_by': self.uploader.username,
            'created_at': self.created_at.isoformat()
        }

class RedactedField(db.Model):
    __tablename__ = 'redacted_fields'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)  # Nullable for live frames
    data_class = db.Column(db.String(50), nullable=False)
    bounding_box_coordinates = db.Column(db.String(100), nullable=False)  # JSON string: "x1,y1,x2,y2"
    original_value = db.Column(db.Text)  # Encrypted PII value
    is_redacted_in_image = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'document_id': self.document_id,
            'data_class': self.data_class,
            'bounding_box_coordinates': self.bounding_box_coordinates,
            'is_redacted_in_image': self.is_redacted_in_image,
            'created_at': self.created_at.isoformat()
        }

    def get_bbox_coords(self):
        """Parse bounding box coordinates from string format"""
        try:
            coords = self.bounding_box_coordinates.split(',')
            return {
                'x1': int(coords[0]),
                'y1': int(coords[1]), 
                'x2': int(coords[2]),
                'y2': int(coords[3])
            }
        except:
            return {'x1': 0, 'y1': 0, 'x2': 0, 'y2': 0}

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)
    redacted_field_id = db.Column(db.Integer, db.ForeignKey('redacted_fields.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # 'reveal', 'upload', 'login', etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    additional_info = db.Column(db.Text)  # JSON string for extra context

    def to_dict(self):
        return {
            'id': self.id,
            'user': self.user.username,
            'user_role': self.user.role,
            'action': self.action,
            'timestamp': self.timestamp.isoformat(),
            'additional_info': self.additional_info
        }