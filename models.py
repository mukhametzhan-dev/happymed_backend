from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON

db = SQLAlchemy()




class Administrator(db.Model):
    __tablename__ = 'administrator'

    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(255), nullable=True)
    last_name = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=True)
    phone = db.Column(db.String(20), unique=True, nullable=True)

class Specialization(db.Model):
    __tablename__ = 'specialization'

    spec_id = db.Column(db.Integer, primary_key=True)
    spec_name = db.Column(db.String(255), nullable=True)

class Doctor(db.Model):
    __tablename__ = 'doctor'

    doctor_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(255), nullable=True)
    last_name = db.Column(db.String(255), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    gender = db.Column(db.Enum('Male', 'Female'), nullable=True)
    spec_id = db.Column(db.Integer, db.ForeignKey('specialization.spec_id'), nullable=True)
    schedule = db.Column(JSON, nullable=True)
    specialization = db.relationship('Specialization', backref=db.backref('doctors', lazy=True))

class Patient(db.Model):
    __tablename__ = 'patient'

    patient_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(255), nullable=True)
    last_name = db.Column(db.String(255), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    gender = db.Column(db.Enum('Male', 'Female',), nullable=True)

class User(db.Model):
    __tablename__ = 'user'

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    password = db.Column(db.String(255), nullable=True)
    role = db.Column(db.Enum('patient', 'doctor', 'administrator'), nullable=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.patient_id'), nullable=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.doctor_id'), nullable=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('administrator.admin_id'), nullable=True)

    patient = db.relationship('Patient', backref=db.backref('users', lazy=True))
    doctor = db.relationship('Doctor', backref=db.backref('users', lazy=True))
    administrator = db.relationship('Administrator', backref=db.backref('users', lazy=True))
class Appointment(db.Model):
    __tablename__ = 'appointments'
    appointment_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.doctor_id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.patient_id'), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    date = db.Column(db.Date, nullable=False)
    day_of_week = db.Column(db.Enum('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'), nullable=False)
    status = db.Column(db.Enum('completed', 'booked'), default='booked', nullable=False)

    doctor = db.relationship('Doctor', backref=db.backref('appointments', lazy=True))
    patient = db.relationship('Patient', backref=db.backref('appointments', lazy=True))
