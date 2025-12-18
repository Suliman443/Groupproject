from app.extensions import db
from sqlalchemy.ext.hybrid import hybrid_property
import hashlib
import hmac

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, index=True)

    # Encrypted fields - store ciphertext
    _email_encrypted = db.Column('email_encrypted', db.Text, nullable=True)
    _fullname_encrypted = db.Column('fullname_encrypted', db.Text, nullable=True)

    # Legacy plaintext fields (for migration compatibility)
    _email_legacy = db.Column('email', db.String(120), nullable=True)
    _fullname_legacy = db.Column('fullname', db.String(100), nullable=True)

    # Email search hash for encrypted email lookups
    email_search_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)

    hashed_password = db.Column(db.String(256), nullable=False)  # Increased size for enhanced hashing
    role = db.Column(db.String(20), default='user')

    # Migration tracking
    encryption_migrated = db.Column(db.Boolean, default=False, nullable=False)

    # Relationships
    created_events = db.relationship('Event', backref='creator', lazy=True)
    created_listings = db.relationship('Listing', backref='creator', lazy=True)
    user_comments = db.relationship('Comment', backref='user_author', lazy=True)

    def __init__(self, email=None, fullname=None, hashed_password=None, role='user', **kwargs):
        """Initialize User with automatic encryption of sensitive fields."""
        super().__init__(**kwargs)

        # Set fields using property setters for automatic encryption
        if email is not None:
            self.email = email
        if fullname is not None:
            self.fullname = fullname
        if hashed_password is not None:
            self.hashed_password = hashed_password
        if role is not None:
            self.role = role

        # Mark as migrated for new users
        self.encryption_migrated = True

    @hybrid_property
    def email(self):
        """Get decrypted email."""
        if self._email_encrypted:
            return self._decrypt_field(self._email_encrypted)
        elif self._email_legacy:
            # Fallback to legacy field during migration
            return self._email_legacy
        return None

    @email.setter
    def email(self, value):
        """Set encrypted email and generate search hash."""
        if value is None:
            self._email_encrypted = None
            self.email_search_hash = None
            return

        # Encrypt the email
        self._email_encrypted = self._encrypt_field(value)

        # Generate deterministic hash for search
        self.email_search_hash = self._generate_search_hash(value.lower().strip())

        # Clear legacy field
        self._email_legacy = None

    @hybrid_property
    def fullname(self):
        """Get decrypted fullname."""
        if self._fullname_encrypted:
            return self._decrypt_field(self._fullname_encrypted)
        elif self._fullname_legacy:
            # Fallback to legacy field during migration
            return self._fullname_legacy
        return None

    @fullname.setter
    def fullname(self, value):
        """Set encrypted fullname."""
        if value is None:
            self._fullname_encrypted = None
            return

        self._fullname_encrypted = self._encrypt_field(value)

        # Clear legacy field
        self._fullname_legacy = None

    def _encrypt_field(self, data):
        """Encrypt a field using the SecurityManager."""
        if not data:
            return None

        try:
            from app.security import security_manager
            return security_manager.encrypt_field(data)
        except Exception as e:
            # Log error without exposing sensitive data
            print(f"Field encryption failed for user {getattr(self, 'id', 'new')}: {type(e).__name__}")
            raise ValueError("Encryption failed") from e

    def _decrypt_field(self, encrypted_data):
        """Decrypt a field using the SecurityManager."""
        if not encrypted_data:
            return None

        try:
            from app.security import security_manager
            return security_manager.decrypt_field(encrypted_data)
        except Exception as e:
            # Log error without exposing sensitive data
            print(f"Field decryption failed for user {getattr(self, 'id', 'unknown')}: {type(e).__name__}")
            raise ValueError("Decryption failed") from e

    def _generate_search_hash(self, email):
        """Generate deterministic hash for email search."""
        try:
            from app.security import security_manager
            # Use first 32 bytes of encryption key as HMAC key
            if hasattr(security_manager, 'encryption_key') and security_manager.encryption_key:
                key = security_manager.encryption_key[:32]
                return hmac.new(key, email.encode('utf-8'), hashlib.sha256).hexdigest()
            else:
                # Fallback to SHA256 if no encryption key available
                return hashlib.sha256(email.encode('utf-8')).hexdigest()
        except Exception:
            # Final fallback
            return hashlib.sha256(email.encode('utf-8')).hexdigest()

    @classmethod
    def find_by_email(cls, email):
        """Find user by email using search hash (works with encrypted emails)."""
        if not email:
            return None

        # Generate search hash for the provided email
        temp_user = cls()
        search_hash = temp_user._generate_search_hash(email.lower().strip())

        return cls.query.filter_by(email_search_hash=search_hash).first()

    @classmethod
    def find_by_email_legacy(cls, email):
        """Find user by email in legacy plaintext field (migration support)."""
        if not email:
            return None
        return cls.query.filter_by(_email_legacy=email).first()

    def set_password_enhanced(self, password):
        """Set password using enhanced security hashing."""
        try:
            from app.security import security_manager
            self.hashed_password = security_manager.hash_sensitive_data(password)
        except Exception:
            # Fallback to standard hashing with salt
            from werkzeug.security import generate_password_hash
            import secrets
            salt = secrets.token_hex(16)
            password_with_salt = password + salt
            self.hashed_password = f"{salt}:pbkdf2:sha256${generate_password_hash(password_with_salt, method='pbkdf2:sha256', salt_length=32)}"

    def check_password(self, password):
        """Check password against stored hash."""
        if not password or not self.hashed_password:
            return False

        try:
            # Try enhanced security format first
            from app.security import security_manager
            if ':' in self.hashed_password and len(self.hashed_password.split(':')) >= 2:
                return security_manager.verify_hash(password, self.hashed_password)
        except Exception:
            pass

        # Fallback to Werkzeug format
        try:
            from werkzeug.security import check_password_hash

            # Handle enhanced format with salt prefix
            if ':' in self.hashed_password and 'pbkdf2:sha256$' in self.hashed_password:
                parts = self.hashed_password.split(':', 2)
                if len(parts) == 3:
                    salt = parts[0]
                    stored_hash = parts[2]
                    password_with_salt = password + salt
                    return check_password_hash(stored_hash, password_with_salt)

            # Standard Werkzeug format
            return check_password_hash(self.hashed_password, password)
        except Exception:
            return False

    def migrate_to_encrypted(self):
        """Migrate legacy plaintext fields to encrypted format."""
        if self.encryption_migrated:
            return True

        try:
            # Migrate email
            if self._email_legacy and not self._email_encrypted:
                self.email = self._email_legacy

            # Migrate fullname
            if self._fullname_legacy and not self._fullname_encrypted:
                self.fullname = self._fullname_legacy

            self.encryption_migrated = True
            return True
        except Exception as e:
            print(f"Migration failed for user {self.id}: {str(e)}")
            return False

    def to_dict(self, include_sensitive=True):
        """Convert user to dictionary with decrypted fields."""
        result = {
            'id': self.id,
            'role': self.role,
            'encryption_migrated': self.encryption_migrated
        }

        if include_sensitive:
            result.update({
                'email': self.email,
                'fullname': self.fullname
            })

        return result

    def __repr__(self):
        return f'<User {self.id}: {self.email or "unknown"}, Role: {self.role}>'