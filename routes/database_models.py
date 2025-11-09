"""
Database Models for User Authentication
Supports:
1. SQLAlchemy (SQL databases like PostgreSQL, MySQL, SQLite)
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    """User model for SQL databases"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone_number = db.Column(db.String(10), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to OMR submissions (optional)
    omr_submissions = db.relationship('OmrSubmission', backref='user', lazy=True)

    def __init__(self, email: str, phone_number: str, password_hash: str):
        """Explicit constructor for static type checkers like Pylance"""
        self.email = email
        self.phone_number = phone_number
        self.password_hash = password_hash

    def __repr__(self):
        return f"<User {self.email}>"

    def to_dict(self):
        """Convert user to dictionary"""
        return {
            "email": self.email,
            "phoneNumber": self.phone_number,
            "created_at": self.created_at.isoformat(),
        }


class OmrSubmission(db.Model):
    """OMR submission model"""
    __tablename__ = 'omr_submissions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    paper_type = db.Column(db.String(50), nullable=False)  # CSAT or GS
    set_option = db.Column(db.String(1), nullable=False)   # A, B, C, D
    total_questions = db.Column(db.Integer, nullable=False)
    total_attempted = db.Column(db.Integer, nullable=False)
    total_correct = db.Column(db.Integer, nullable=False)
    skipped = db.Column(db.Integer, nullable=False)
    score_percentage = db.Column(db.Float, nullable=False)
    answers = db.Column(db.JSON, nullable=False)  # Store answers as JSON
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(
        self,
        user_id: int,
        paper_type: str,
        set_option: str,
        total_questions: int,
        total_attempted: int,
        total_correct: int,
        skipped: int,
        score_percentage: float,
        answers: dict,
    ):
        self.user_id = user_id
        self.paper_type = paper_type
        self.set_option = set_option
        self.total_questions = total_questions
        self.total_attempted = total_attempted
        self.total_correct = total_correct
        self.skipped = skipped
        self.score_percentage = score_percentage
        self.answers = answers

    def __repr__(self):
        return f"<OmrSubmission {self.id} - User {self.user_id}>"
