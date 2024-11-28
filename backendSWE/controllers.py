# controllers.py
import os
from werkzeug.utils import secure_filename
from models import Appointment, Doctor, Specialization, db, Patient, User, Administrator
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import current_app
import requests
import logging

def register_patient(data):
    try:
        # Check if email already exists in Patient table
        if Patient.query.filter_by(email=data['email']).first():
            return {'error': 'Email already exists from 17'}, 400

        date_of_birth = datetime.strptime(
            f"{data['dateOfBirthYear']}-{data['dateOfBirthMonth']}-{data['dateOfBirthDay']}",
            '%Y-%m-%d'
        ).date()
        
        hashed_password = generate_password_hash(data['password'])

        new_patient = Patient(
            first_name=data['firstName'],
            last_name=data['lastName'],
            date_of_birth=date_of_birth,
            email=data['email'],
            phone=data['mobileNumber'],
            gender=data.get('gender', 'Male')
        )
        # print(new_patient.to_dict())
        print(new_patient.email)
        db.session.add(new_patient)
        db.session.commit()


        new_user = User(
            password=hashed_password,
            role='patient',
            patient_id=new_patient.patient_id
        )
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'Patient registered successfully'}, 201
    except IntegrityError:
        # print(IntegrityError.__cause__)
        
        db.session.rollback()
        return {'error': 'Email already exists 52'}, 400
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400

def register_doctor(data, medical_certificate):

    try:
        logging.info(f"Data: {data}")
        print(data)
        # Check if email already exists in Doctor table
        if Doctor.query.filter_by(email=data['email']).first():
            return {'error': 'Email already exists Doctor 57'}, 400

        date_of_birth = datetime.strptime(
            f"{data['dateOfBirthYear']}-{data['dateOfBirthMonth']}-{data['dateOfBirthDay']}",
            '%Y-%m-%d'
        ).date()


        # Get specialization
        # convert 004 to 4
        print(int(data['specialty']))

        # spec = Specialization.query.filter_by(spec_id=int(data['specialty'])).first()

        # if not spec:
        #     return {'error': 'Specialization not found'}, 400
        
        # print(spec)
        # print(spec.spec_id)
        # print(spec.spec_name)
        # print(data.specialty)
        # if not spec:
        #     return {'error': 'Specialization not found'}, 400

        hashed_password = generate_password_hash(data['password'])

        new_doctor = Doctor(
            first_name=data['firstName'],
            last_name=data['lastName'],
            date_of_birth=date_of_birth,
            email=data['email'],
            phone=data['mobileNumber'],
            spec_id=int(data['specialty']),
            
        )
        db.session.add(new_doctor)
        db.session.commit()

        new_user = User(
            password=hashed_password,
            role='doctor',
            doctor_id=new_doctor.doctor_id
        )
        db.session.add(new_user)
        db.session.commit()

        # Save the medical certificate file
        if medical_certificate:
            filename = secure_filename(medical_certificate.filename)
            upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            medical_certificate.save(upload_path)

        return {'message': 'Doctor registered successfully'}, 201
    except IntegrityError:
        db.session.rollback()
        return {'error': 'Email already exists doctor 99'}, 400
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400
def save_schedule(data):
    try:
        email = data.get('email')
        schedule = data.get('schedule')

        doctor = Doctor.query.filter_by(email=email).first()
        if not doctor:
            return {'error': 'Doctor not found'}, 404

        doctor.schedule = schedule
        db.session.commit()

        return {'message': 'Schedule saved successfully', 'schedule': doctor.schedule}, 200
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400

def authenticate_user(email, password):
    user = User.query.join(Patient, User.patient_id == Patient.patient_id, isouter=True) \
                     .join(Doctor, User.doctor_id == Doctor.doctor_id, isouter=True) \
                     .join(Administrator, User.admin_id == Administrator.admin_id, isouter=True) \
                     .filter((Patient.email == email) | (Doctor.email == email) | (Administrator.email == email)).first()

    if user and check_password_hash(user.password, password):
        user_data = {
            'user_id': user.user_id,
            'role': user.role
        }
        if user.role == 'patient':
            user_data.update({
                'first_name': user.patient.first_name,
                'last_name': user.patient.last_name,
                'email': user.patient.email,
                'phone': user.patient.phone,
                'gender': user.patient.gender
            })
        elif user.role == 'doctor':
            user_data.update({
                'first_name': user.doctor.first_name,
                'last_name': user.doctor.last_name,
                'email': user.doctor.email,
                'phone': user.doctor.phone,
                'gender': user.doctor.gender,
                # 'specialization': user.doctor.specialization.spec_name
                'specialization': user.doctor.spec_id # ska
            })
        elif user.role == 'administrator':
            user_data.update({
                'first_name': user.administrator.first_name,
                'last_name': user.administrator.last_name,
                'email': user.administrator.email,
                'phone': user.administrator.phone
            })

        return {'status': 'success', 'message': 'Login successful', 'user': user_data}, 200
    else:
        return {'status': 'fail', 'error': 'Invalid email or password'}, 401

def edit_patient_profile(email, data):
    patient = Patient.query.filter_by(email=email).first()
    if not patient:
        return {'error': 'Patient not found'}, 404

    try:
        if 'firstName' in data:
            patient.first_name = data['firstName']
        if 'lastName' in data:
            patient.last_name = data['lastName']
        if all(k in data for k in ('dateOfBirthYear', 'dateOfBirthMonth', 'dateOfBirthDay')):
            patient.date_of_birth = datetime.strptime(
                f"{data['dateOfBirthYear']}-{data['dateOfBirthMonth']}-{data['dateOfBirthDay']}",
                '%Y-%m-%d'
            ).date()
        if 'mobileNumber' in data:
            patient.phone = data['mobileNumber']
        if 'gender' in data:
            patient.gender = data['gender']
        if 'password' in data:
            user = User.query.filter_by(patient_id=patient.patient_id).first()
            user.password = generate_password_hash(data['password'])

        db.session.commit()
        return {'message': 'Profile updated successfully'}, 200
    except Exception as e:
        return {'error': str(e)}, 400
def get_all_doctors():
    doctors = Doctor.query.all()

    doctors_list = [{
        'doctor_id': doctor.doctor_id,
        'first_name': doctor.first_name,
        'last_name': doctor.last_name,
        'date_of_birth': doctor.date_of_birth.strftime('%Y-%m-%d'),
        'email': doctor.email,
        'phone': doctor.phone,
        'schedule': doctor.schedule,
        'specialization': {
            'spec_id': doctor.specialization.spec_id,
            'spec_name': doctor.specialization.spec_name    }
        


    }
        for doctor in doctors

    ]
    return doctors_list, 200
    
def get_all_patients():
    patients = Patient.query.all()

    patients_list = [{
        'patient_id': patient.patient_id,
        'first_name': patient.first_name,
        'last_name': patient.last_name,
        'date_of_birth': patient.date_of_birth.strftime('%Y-%m-%d'),
        'email': patient.email,
        'phone': patient.phone,
        'gender': patient.gender
    } for patient in patients]
    return patients_list, 200

def send_password_reset_email(email):
    user = User.query.join(Patient, User.patient_id == Patient.patient_id, isouter=True) \
                     .join(Doctor, User.doctor_id == Doctor.doctor_id, isouter=True) \
                     .join(Administrator, User.admin_id == Administrator.admin_id, isouter=True) \
                     .filter((Patient.email == email) | (Doctor.email == email) | (Administrator.email == email)).first()

    if not user:
        return {'error': 'Email does not exist'}, 404

    try:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        token = serializer.dumps(email, salt='password-reset-salt')

        reset_url = f'http://localhost:5173/reset-password/{token}'
        send_reset_password_email(email, f"{user.role.capitalize()} {user.user_id}", reset_url)

        return {'message': 'Password reset email sent'}, 200
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return {'error': 'An internal error occurred'}, 500

def send_reset_password_email(to_email, to_name, reset_url):
    api_url = 'https://api.smtp2go.com/v3/email/send'
    api_key = current_app.config['SMTP2GO_API_KEY']  # Use config

    headers = {
        'Content-Type': 'application/json',
        'X-Smtp2go-Api-Key': api_key,
        'accept': 'application/json'
    }

    payload = {
        "sender": current_app.config['SMTP2GO_SENDER'],  # Use config
        "to": [to_email],
        "subject": "Password Reset Request",
        "html_body": f"""
            <p>Hello {to_name},</p>
            <p>Please click the link below to reset your password:</p>
            <p><a href='{reset_url}'>Reset Password</a></p>
            <p>If you did not request this, please ignore this email.</p>
        """
    }

    response = requests.post(api_url, headers=headers, json=payload)
    if response.status_code != 200:
        logging.error(f"Failed to send email: {response.text}")
        raise Exception("Failed to send email")

def reset_password(token, method, data=None):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

    if method == 'GET':
        try:
            # Validate token
            email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
            return {'message': 'Token is valid', 'email': email}, 200
        except SignatureExpired:
            return {'error': 'The token is expired'}, 400
        except BadSignature:
            return {'error': 'Invalid token'}, 400

    elif method == 'POST':
        password = data.get('password')
        confirm_password = data.get('confirmPassword')

        if not password or not confirm_password:
            return {'error': 'Fields cannot be empty!'}, 400

        if password != confirm_password:
            return {'error': 'Passwords do not match!'}, 400

        try:
            # Validate token again
            email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        except SignatureExpired:
            return {'error': 'The token is expired'}, 400
        except BadSignature:
            return {'error': 'Invalid token'}, 400

        user = User.query.join(Patient, User.patient_id == Patient.patient_id, isouter=True) \
                         .join(Doctor, User.doctor_id == Doctor.doctor_id, isouter=True) \
                         .join(Administrator, User.admin_id == Administrator.admin_id, isouter=True) \
                         .filter((Patient.email == email) | (Doctor.email == email) | (Administrator.email == email)).first()

        if not user:
            return {'error': 'User not found!'}, 404

        # Update the password
        user.password = generate_password_hash(password)
        db.session.commit()

        return {'message': 'Your password has been reset successfully!'}, 200
def get_schedule(email):
    
    try:
        doctor = Doctor.query.filter_by(email=email).first()
        if not doctor:

            return {'error': 'Doctor not found'}, 404
        

        return {'schedule': doctor.schedule}, 200
    except Exception as e:
        return {'error': str(e)}, 400

def verify_id(identification_number):
    try:
        dict = {
            'Mars': 220107126,
            'Sanzhar': 200107052,
            'MuratAbdilda': 77777777
        }     
        # print(int(identification_number) == 200107052)
        if int(identification_number) in dict.values():
            print("verified")
            return {'exists': True, 'role': 'admin', 'status': 'verified'}, 200
            
        # Check in Patient table

        # Check in Administrator table
        # administrator = Administrator.query.filter_by(admin_id=identification_number).first()
        # if administrator:

            return {'exists': True, 'role': 'administrator'}, 200

        # If not found in any table
        return {'exists': False}, 404
    except Exception as e:
        return {'error': str(e)}, 400
def register_admin(data):
    try:
        # Check if email already exists in Administrator table
        
        if Administrator.query.filter_by(email=data['email']).first() or Patient.query.filter_by(email=data['email']).first() or Doctor.query.filter_by(email=data['email']).first(): 

            return {'error': 'Email already exists'}, 400

        hashed_password = generate_password_hash(data['password'])

        new_admin = Administrator(
            first_name=data['firstName'],
            last_name=data['lastName'],
            email=data['email'],
            phone=data['number']
        )
        print(data['email'])
        print(data['number'])
        db.session.add(new_admin)
        db.session.commit()

        new_user = User(
            password=hashed_password,
            role='administrator',
            admin_id=new_admin.admin_id
        )
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'Administrator registered successfully', 'status': 'success'}, 201
    except IntegrityError:
        db.session.rollback()
        return {'error': 'Email already exists'}, 400
    except Exception as e:
        db.session.rollback()
        print(e)
        return {'error': str(e)}, 400
def get_patients(query=None):
    try:
        if query:
            print(query)
            patients = Patient.query.filter(
                (Patient.first_name.ilike(f'%{query}%')) |
                (Patient.last_name.ilike(f'%{query}%')) |
                (Patient.email.ilike(f'%{query}%'))
            ).all()
        else:
            patients = Patient.query.all()

        patients_list = [{
            'firstName': patient.first_name,
            'lastName': patient.last_name,
            'email': patient.email,
            'role': 'patient'
        } for patient in patients]

        return patients_list, 200
    except Exception as e:
        return {'error': str(e)}, 400

def get_doctors(query=None):
    try:
        if query:
            doctors = Doctor.query.filter(
                (Doctor.first_name.ilike(f'%{query}%')) |
                (Doctor.last_name.ilike(f'%{query}%')) |
                (Doctor.email.ilike(f'%{query}%'))
            ).all()
        else:
            doctors = Doctor.query.all()

        doctors_list = [{
            'firstName': doctor.first_name,
            'lastName': doctor.last_name,
            'email': doctor.email,
            'role': 'doctor'
        } for doctor in doctors]

        return doctors_list, 200
    except Exception as e:
        return {'error': str(e)}, 400
def make_appointment(data):
    try:
        doctor_id = data['doctor']
        description = data['description']
        time_slot = data['timeSlot']
        user_id = data['patient_id']
        
        print(data)

        # Check if doctor exists
        doctor = Doctor.query.filter_by(doctor_id=doctor_id).first()
        if not doctor:
            return {'error': 'Doctor not found'}, 404

        # Fetch patient_id using user_id
        user = User.query.filter_by(user_id=user_id).first()
        if not user or not user.patient_id:
            return {'error': 'Patient not found'}, 404

        patient_id = user.patient_id
        print(patient_id)

        start_time_str, end_time_str = time_slot['time'].split('-')
        start_time = datetime.strptime(start_time_str, '%H:%M').time()
        end_time = datetime.strptime(end_time_str, '%H:%M').time()
        date = datetime.strptime(time_slot['date'], '%d.%m.%Y').date()
        day_of_week = time_slot['day']

        new_appointment = Appointment(
            doctor_id=doctor_id,
            description=description,
            start_time=start_time,
            end_time=end_time,
            date=date,
            day_of_week=day_of_week,
            patient_id=patient_id
        )
        db.session.add(new_appointment)
        db.session.commit()

        return {'message': 'Appointment created successfully'}, 201
    
    except IntegrityError as e:
        db.session.rollback()
        logging.error(f"IntegrityError: {e}")
        return {'error': 'Failed to create appointment due to integrity error'}, 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Exception: {e}")
        return {'error': str(e)}, 400
def get_appointments_for_doctor(email):
    try:
        doctor = Doctor.query.filter_by(email=email).first()
        if not doctor:
            return {'error': 'Doctor not found'}, 404

        appointments = db.session.query(Appointment, Patient).join(Patient, Appointment.patient_id == Patient.patient_id).filter(Appointment.doctor_id == doctor.doctor_id).all()
        
        appointments_list = [{
            'appointment_id': appointment.Appointment.appointment_id,
            'description': appointment.Appointment.description,
            'start_time': appointment.Appointment.start_time.strftime('%H:%M'),
            'end_time': appointment.Appointment.end_time.strftime('%H:%M'),
            'date': appointment.Appointment.date.strftime('%Y-%m-%d'),
            'day_of_week': appointment.Appointment.day_of_week,
            'status': appointment.Appointment.status,
            'patient_name': f"{appointment.Patient.first_name} {appointment.Patient.last_name}"
        } for appointment in appointments]

        return {'appointments': appointments_list}, 200
    except Exception as e:
        return {'error': str(e)}, 400
def get_appointments_for_patient(user_id):
    try:
        # Fetch patient_id using user_id
        user = User.query.filter_by(user_id=user_id).first()
        if not user or not user.patient_id:
            return {'error': 'Patient not found'}, 404

        patient_id = user.patient_id

        appointments = Appointment.query.filter_by(patient_id=patient_id).all()
        appointments_list = [{
            'appointment_id': appointment.appointment_id,
            'doctor_id': appointment.doctor_id,
            'description': appointment.description,
            'start_time': appointment.start_time.strftime('%H:%M'),
            'end_time': appointment.end_time.strftime('%H:%M'),
            'date': appointment.date.strftime('%Y-%m-%d'),
            'day_of_week': appointment.day_of_week,
            'status': appointment.status
        } for appointment in appointments]

        return {'appointments': appointments_list}, 200
    except Exception as e:
        return {'error': str(e)}, 400
def complete_appointment(data):
    try:
        appointment_id = data['appointment_id']

        # Fetch the appointment
        appointment = Appointment.query.filter_by(appointment_id=appointment_id).first()
        if not appointment:
            return {'error': 'Appointment not found'}, 404

        # Update the status to completed
        appointment.status = 'completed'
        db.session.commit()

        return {'message': 'Appointment status updated to completed'}, 200
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 400