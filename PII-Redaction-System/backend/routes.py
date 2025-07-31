from flask import Flask, request, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
import os
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
import cv2
import base64

from models import db, User, UserPermission, SystemRedactionRule, Document, RedactedField, AuditLog
from auth import (
    authenticate_user, create_user_token, role_required, 
    log_action, get_current_user, check_data_class_permission
)
from pii_redaction_service import PIIRedactionService

# Initialize redaction service (will be set in app.py)
redaction_service = None

def init_routes(app, pii_service):
    global redaction_service
    redaction_service = pii_service

    # Authentication Routes
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            role = data.get('role')  # For demo purposes
            
            if not username or not password:
                return jsonify({'error': 'Username and password required'}), 400
            
            # For demo: create user if doesn't exist with specified role
            user = User.query.filter_by(username=username).first()
            if not user and role:
                from auth import hash_password
                user = User(
                    username=username,
                    password_hash=hash_password(password),
                    role=role
                )
                db.session.add(user)
                db.session.commit()
                
                # Create default permissions for non-admin users
                if role != 'Admin':
                    default_permissions = ['Name', 'Aadhaar Number', 'Phone Number', 'Date of Birth', 'Father Name']
                    for pii_class in default_permissions:
                        permission = UserPermission(
                            user_id=user.id,
                            data_class=pii_class,
                            can_view=True,
                            can_reveal=(role == 'Intern')
                        )
                        db.session.add(permission)
                    db.session.commit()
            
            # Authenticate user
            authenticated_user = authenticate_user(username, password)
            if not authenticated_user:
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Create token
            token = create_user_token(authenticated_user)
            
            # Log login action
            log_action('login', authenticated_user.id)
            
            return jsonify({
                'token': token,
                'user': authenticated_user.to_dict(),
                'message': 'Login successful'
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/auth/logout', methods=['POST'])
    @jwt_required()
    def logout():
        try:
            log_action('logout')
            return jsonify({'message': 'Logout successful'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # User Management Routes (Admin only)
    @app.route('/api/users', methods=['GET'])
    @role_required('Admin')
    def get_users():
        try:
            users = User.query.all()
            users_data = []
            
            for user in users:
                user_data = user.to_dict()
                # Get user permissions
                permissions = {}
                user_permissions = UserPermission.query.filter_by(user_id=user.id).all()
                for perm in user_permissions:
                    permissions[perm.data_class] = {
                        'can_view': perm.can_view,
                        'can_reveal': perm.can_reveal
                    }
                user_data['permissions'] = permissions
                users_data.append(user_data)
            
            return jsonify({'users': users_data})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/users/<int:user_id>/permissions', methods=['PUT'])
    @role_required('Admin')
    def update_user_permissions(user_id):
        try:
            data = request.get_json()
            permissions_data = data.get('permissions', {})
            
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Update permissions
            for data_class, perms in permissions_data.items():
                permission = UserPermission.query.filter_by(
                    user_id=user_id,
                    data_class=data_class
                ).first()
                
                if permission:
                    permission.can_view = perms.get('can_view', False)
                    permission.can_reveal = perms.get('can_reveal', False)
                else:
                    permission = UserPermission(
                        user_id=user_id,
                        data_class=data_class,
                        can_view=perms.get('can_view', False),
                        can_reveal=perms.get('can_reveal', False)
                    )
                    db.session.add(permission)
            
            db.session.commit()
            
            log_action('update_permissions', additional_info=f'Updated permissions for user {user.username}')
            
            return jsonify({'message': 'Permissions updated successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # System Redaction Rules (Admin only)
    @app.route('/api/system-redaction-rules', methods=['GET'])
    @role_required('Admin')
    def get_system_rules():
        try:
            rules = SystemRedactionRule.query.all()
            return jsonify({'rules': [rule.to_dict() for rule in rules]})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/system-redaction-rules', methods=['PUT'])
    @role_required('Admin')
    def update_system_rules():
        try:
            data = request.get_json()
            rules_data = data.get('rules', {})
            
            for field_name, rule_config in rules_data.items():
                rule = SystemRedactionRule.query.filter_by(field_name=field_name).first()
                
                if rule:
                    rule.is_redacted = rule_config.get('is_redacted', True)
                    rule.custom_regex = rule_config.get('custom_regex', '')
                    rule.redaction_template = rule_config.get('redaction_template', 'Default')
                else:
                    rule = SystemRedactionRule(
                        field_name=field_name,
                        is_redacted=rule_config.get('is_redacted', True),
                        custom_regex=rule_config.get('custom_regex', ''),
                        redaction_template=rule_config.get('redaction_template', 'Default')
                    )
                    db.session.add(rule)
            
            db.session.commit()
            
            log_action('update_system_rules')
            
            return jsonify({'message': 'System rules updated successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # Image Redaction Routes
    @app.route('/api/redact-image', methods=['POST'])
    @jwt_required()
    def redact_image():
        try:
            if 'image' not in request.files:
                return jsonify({'error': 'No image file provided'}), 400
            
            file = request.files['image']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            # Save uploaded file
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(upload_path)
            
            # Create document record
            user_id = get_jwt_identity()
            document = Document(
                original_filename=filename,
                original_storage_path=upload_path,
                uploaded_by_user_id=user_id
            )
            db.session.add(document)
            db.session.commit()
            
            # Process image for redaction
            result = redaction_service.process_image_for_redaction(upload_path, document.id)
            
            if not result['success']:
                return jsonify({'error': result['error']}), 500
            
            # Save redacted image
            redacted_filename = f"redacted_{unique_filename}"
            redacted_path = os.path.join(current_app.config['UPLOAD_FOLDER'], redacted_filename)
            cv2.imwrite(redacted_path, result['redacted_image'])
            
            document.redacted_storage_path = redacted_path
            db.session.commit()
            
            # Convert redacted image to base64 for frontend
            redacted_base64 = redaction_service.image_to_base64(result['redacted_image'])
            
            # Filter redacted fields based on user permissions
            user = get_current_user()
            filtered_fields = []
            
            for field in result['redacted_fields']:
                if user.role == 'Admin' or check_data_class_permission(user.id, field['data_class'], 'view'):
                    field_data = field.copy()
                    field_data['can_reveal'] = (user.role == 'Admin' or 
                                               check_data_class_permission(user.id, field['data_class'], 'reveal'))
                    filtered_fields.append(field_data)
            
            log_action('upload_image', document_id=document.id)
            
            return jsonify({
                'document_id': document.id,
                'redacted_image': redacted_base64,
                'redacted_fields': filtered_fields,
                'message': 'Image processed successfully'
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # Live Camera Frame Processing
    @app.route('/api/live-redact-frame', methods=['POST'])
    @jwt_required()
    def live_redact_frame():
        try:
            data = request.get_json()
            frame_data = data.get('frame')
            
            if not frame_data:
                return jsonify({'error': 'No frame data provided'}), 400
            
            # Process frame for live detection
            result = redaction_service.process_frame_for_live_detection(frame_data)
            
            if not result['success']:
                return jsonify({'error': result['error']}), 500
            
            # Filter detections based on user permissions
            user = get_current_user()
            filtered_detections = []
            
            for detection in result['detections']:
                if user.role == 'Admin' or check_data_class_permission(user.id, detection['class'], 'view'):
                    filtered_detections.append(detection)
            
            return jsonify({
                'detections': filtered_detections,
                'success': True
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # Reveal Functionality
    @app.route('/api/reveal/<int:field_id>', methods=['GET'])
    @jwt_required()
    def reveal_field(field_id):
        try:
            field = RedactedField.query.get(field_id)
            if not field:
                return jsonify({'error': 'Field not found'}), 404
            
            user = get_current_user()
            
            # Check permissions
            if user.role != 'Admin' and not check_data_class_permission(user.id, field.data_class, 'reveal'):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Reveal the field
            result = redaction_service.reveal_redacted_field(field_id)
            
            if not result['success']:
                return jsonify({'error': result['error']}), 500
            
            # Log reveal action
            log_action('reveal', redacted_field_id=field_id, 
                      additional_info=f'Revealed {field.data_class}')
            
            return jsonify({
                'original_value': result['original_value'],
                'data_class': result['data_class'],
                'message': 'Field revealed successfully'
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # Audit Log (Admin only)
    @app.route('/api/audit-log', methods=['GET'])
    @role_required('Admin')
    def get_audit_log():
        try:
            logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
            return jsonify({'logs': [log.to_dict() for log in logs]})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # Download Redacted File
    @app.route('/api/download-redacted/<int:document_id>', methods=['GET'])
    @jwt_required()
    def download_redacted(document_id):
        try:
            document = Document.query.get(document_id)
            if not document:
                return jsonify({'error': 'Document not found'}), 404
            
            if not document.redacted_storage_path or not os.path.exists(document.redacted_storage_path):
                return jsonify({'error': 'Redacted file not found'}), 404
            
            log_action('download', document_id=document_id)
            
            return send_file(
                document.redacted_storage_path,
                as_attachment=True,
                download_name=f"redacted_{document.original_filename}"
            )
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return app