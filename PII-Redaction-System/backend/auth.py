from functools import wraps
from flask import request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
import bcrypt
from models import User, UserPermission, AuditLog, db
from datetime import datetime, timedelta

def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    """Check if password matches the hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def authenticate_user(username, password):
    """Authenticate user and return user object if valid"""
    user = User.query.filter_by(username=username).first()
    if user and check_password(password, user.password_hash):
        return user
    return None

def create_user_token(user):
    """Create JWT token for user"""
    additional_claims = {
        "role": user.role,
        "user_id": user.id,
        "username": user.username
    }
    
    # Get user permissions
    permissions = {}
    user_permissions = UserPermission.query.filter_by(user_id=user.id).all()
    for perm in user_permissions:
        permissions[perm.data_class] = {
            'can_view': perm.can_view,
            'can_reveal': perm.can_reveal
        }
    
    additional_claims["permissions"] = permissions
    
    return create_access_token(
        identity=user.id,
        additional_claims=additional_claims,
        expires_delta=timedelta(hours=24)
    )

def role_required(*allowed_roles):
    """Decorator to check if user has required role"""
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            if user.role not in allowed_roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def permission_required(data_class, permission_type):
    """Decorator to check if user has specific permission for a data class"""
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Admin has all permissions
            if user.role == 'Admin':
                return f(*args, **kwargs)
            
            # Check specific permission
            permission = UserPermission.query.filter_by(
                user_id=user_id,
                data_class=data_class
            ).first()
            
            if not permission:
                return jsonify({'error': f'No permissions for {data_class}'}), 403
            
            if permission_type == 'view' and not permission.can_view:
                return jsonify({'error': f'Cannot view {data_class}'}), 403
            
            if permission_type == 'reveal' and not permission.can_reveal:
                return jsonify({'error': f'Cannot reveal {data_class}'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_action(action, user_id=None, document_id=None, redacted_field_id=None, additional_info=None):
    """Log user actions for audit trail"""
    try:
        if not user_id:
            user_id = get_jwt_identity()
        
        audit_log = AuditLog(
            user_id=user_id,
            document_id=document_id,
            redacted_field_id=redacted_field_id,
            action=action,
            additional_info=additional_info
        )
        
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log action: {e}")

def get_current_user():
    """Get current authenticated user"""
    try:
        user_id = get_jwt_identity()
        return User.query.get(user_id)
    except:
        return None

def check_data_class_permission(user_id, data_class, permission_type):
    """Check if user has permission for specific data class"""
    user = User.query.get(user_id)
    
    # Admin has all permissions
    if user and user.role == 'Admin':
        return True
    
    permission = UserPermission.query.filter_by(
        user_id=user_id,
        data_class=data_class
    ).first()
    
    if not permission:
        return False
    
    if permission_type == 'view':
        return permission.can_view
    elif permission_type == 'reveal':
        return permission.can_reveal
    
    return False