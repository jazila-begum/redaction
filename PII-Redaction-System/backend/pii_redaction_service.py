import os
import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFilter
import torch
from ultralytics import YOLO
import pytesseract
import base64
import io
from cryptography.fernet import Fernet
import re
from models import SystemRedactionRule, RedactedField, db

class PIIRedactionService:
    def __init__(self, model_path):
        self.model_path = model_path
        self.model = None
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # PII class mapping - adjust based on your best.pt model
        self.pii_classes = {
            0: 'Name',
            1: 'Aadhaar Number',
            2: 'Phone Number', 
            3: 'Date of Birth',
            4: 'Father Name',
            5: 'Address'
        }
        
        self.load_model()

    def load_model(self):
        """Load the YOLO model from best.pt"""
        try:
            if os.path.exists(self.model_path):
                self.model = YOLO(self.model_path)
                print(f"Model loaded successfully from {self.model_path}")
            else:
                print(f"Model file not found at {self.model_path}")
                # Create a dummy model for testing
                self.create_dummy_model()
        except Exception as e:
            print(f"Error loading model: {e}")
            self.create_dummy_model()

    def create_dummy_model(self):
        """Create a dummy model for testing when best.pt is not available"""
        print("Creating dummy model for testing purposes")
        self.model = None

    def detect_pii_in_image(self, image_array):
        """Detect PII in an image using the loaded model"""
        detections = []
        
        if self.model is None:
            # Return dummy detections for testing
            height, width = image_array.shape[:2]
            detections = [
                {
                    'class': 'Name',
                    'confidence': 0.95,
                    'bbox': [int(width*0.1), int(height*0.1), int(width*0.4), int(height*0.2)]
                },
                {
                    'class': 'Aadhaar Number',
                    'confidence': 0.90,
                    'bbox': [int(width*0.1), int(height*0.3), int(width*0.6), int(height*0.4)]
                }
            ]
        else:
            try:
                # Run inference
                results = self.model(image_array)
                
                for result in results:
                    boxes = result.boxes
                    if boxes is not None:
                        for box in boxes:
                            class_id = int(box.cls)
                            confidence = float(box.conf)
                            bbox = box.xyxy[0].tolist()  # [x1, y1, x2, y2]
                            
                            if class_id in self.pii_classes and confidence > 0.5:
                                detections.append({
                                    'class': self.pii_classes[class_id],
                                    'confidence': confidence,
                                    'bbox': [int(coord) for coord in bbox]
                                })
            except Exception as e:
                print(f"Error during inference: {e}")
        
        return detections

    def extract_text_from_region(self, image, bbox):
        """Extract text from a specific region using OCR"""
        try:
            x1, y1, x2, y2 = bbox
            roi = image[y1:y2, x1:x2]
            
            # Convert to PIL Image for better OCR
            pil_image = Image.fromarray(cv2.cvtColor(roi, cv2.COLOR_BGR2RGB))
            text = pytesseract.image_to_string(pil_image).strip()
            return text
        except Exception as e:
            print(f"Error extracting text: {e}")
            return ""

    def encrypt_text(self, text):
        """Encrypt sensitive text"""
        return self.cipher_suite.encrypt(text.encode()).decode()

    def decrypt_text(self, encrypted_text):
        """Decrypt sensitive text"""
        try:
            return self.cipher_suite.decrypt(encrypted_text.encode()).decode()
        except:
            return "Decryption failed"

    def apply_redaction_to_image(self, image_array, detections, system_rules=None):
        """Apply redaction to image based on detections and system rules"""
        if system_rules is None:
            system_rules = self.get_system_redaction_rules()
        
        # Convert to PIL Image for easier manipulation
        image = Image.fromarray(cv2.cvtColor(image_array, cv2.COLOR_BGR2RGB))
        draw = ImageDraw.Draw(image)
        
        redacted_fields_data = []
        
        for detection in detections:
            pii_class = detection['class']
            bbox = detection['bbox']
            
            # Check if this PII class should be redacted based on system rules
            should_redact = True
            if pii_class in system_rules:
                should_redact = system_rules[pii_class].get('is_redacted', True)
            
            if should_redact:
                # Extract original text for potential reveal
                original_text = self.extract_text_from_region(image_array, bbox)
                
                # Apply redaction (black box)
                draw.rectangle(bbox, fill='black')
                
                # Store redacted field data
                redacted_fields_data.append({
                    'data_class': pii_class,
                    'bbox': f"{bbox[0]},{bbox[1]},{bbox[2]},{bbox[3]}",
                    'original_value': self.encrypt_text(original_text) if original_text else "",
                    'confidence': detection['confidence']
                })
        
        # Convert back to CV2 format
        redacted_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        
        return redacted_image, redacted_fields_data

    def get_system_redaction_rules(self):
        """Get current system redaction rules"""
        rules = {}
        system_rules = SystemRedactionRule.query.all()
        
        for rule in system_rules:
            rules[rule.field_name] = {
                'is_redacted': rule.is_redacted,
                'custom_regex': rule.custom_regex,
                'redaction_template': rule.redaction_template
            }
        
        return rules

    def process_image_for_redaction(self, image_path, document_id=None):
        """Main method to process an image for PII redaction"""
        try:
            # Load image
            image_array = cv2.imread(image_path)
            if image_array is None:
                raise Exception("Could not load image")
            
            # Detect PII
            detections = self.detect_pii_in_image(image_array)
            
            # Apply redaction
            redacted_image, redacted_fields_data = self.apply_redaction_to_image(
                image_array, detections
            )
            
            # Save redacted fields to database if document_id provided
            saved_fields = []
            if document_id:
                for field_data in redacted_fields_data:
                    redacted_field = RedactedField(
                        document_id=document_id,
                        data_class=field_data['data_class'],
                        bounding_box_coordinates=field_data['bbox'],
                        original_value=field_data['original_value'],
                        is_redacted_in_image=True
                    )
                    db.session.add(redacted_field)
                    saved_fields.append(redacted_field)
                
                db.session.commit()
            
            return {
                'redacted_image': redacted_image,
                'detections': detections,
                'redacted_fields': [field.to_dict() for field in saved_fields],
                'success': True
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def process_frame_for_live_detection(self, frame_data):
        """Process a single frame for live camera detection (no redaction)"""
        try:
            # Decode base64 frame to image
            if isinstance(frame_data, str):
                # Remove data URL prefix if present
                if 'data:image' in frame_data:
                    frame_data = frame_data.split(',')[1]
                
                # Decode base64
                image_data = base64.b64decode(frame_data)
                image = Image.open(io.BytesIO(image_data))
                image_array = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            else:
                image_array = frame_data
            
            # Detect PII (no redaction applied)
            detections = self.detect_pii_in_image(image_array)
            
            # Return only bounding boxes and classes for frontend overlay
            live_detections = []
            for detection in detections:
                live_detections.append({
                    'class': detection['class'],
                    'bbox': detection['bbox'],
                    'confidence': detection['confidence']
                })
            
            return {
                'detections': live_detections,
                'success': True
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def reveal_redacted_field(self, field_id):
        """Reveal the original value of a redacted field"""
        try:
            field = RedactedField.query.get(field_id)
            if not field:
                return {'success': False, 'error': 'Field not found'}
            
            if not field.original_value:
                return {'success': False, 'error': 'No original value stored'}
            
            decrypted_value = self.decrypt_text(field.original_value)
            
            return {
                'success': True,
                'original_value': decrypted_value,
                'data_class': field.data_class
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def image_to_base64(self, image_array):
        """Convert image array to base64 string"""
        try:
            _, buffer = cv2.imencode('.jpg', image_array)
            image_base64 = base64.b64encode(buffer).decode('utf-8')
            return f"data:image/jpeg;base64,{image_base64}"
        except Exception as e:
            print(f"Error converting image to base64: {e}")
            return None