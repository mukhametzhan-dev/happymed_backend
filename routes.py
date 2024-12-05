# routes.py
from flask import Blueprint, request, jsonify

from controllers import (
    get_all_doctors,
    register_admin,
    register_patient,
    register_doctor,
    authenticate_user,
    edit_patient_profile,
    get_all_patients,
    send_password_reset_email,
    reset_password,
    save_schedule,
    get_schedule,
    verify_id,
    get_doctors,
    get_patients,
    make_appointment,
    get_appointments_for_doctor,
    get_appointments_for_patient,
    complete_appointment

)
import os


routes = Blueprint('routes', __name__)

@routes.route('/register', methods=['POST'])
def register():
    data = request.form.to_dict()
    medical_certificate = request.files.get('medicalCertificate')
    if data.get('role') == 'doctor':
        response, status_code = register_doctor(data, medical_certificate)
    else:
        response, status_code = register_patient(data)
    return jsonify(response), status_code

@routes.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    response, status_code = authenticate_user(data['email'], data['password'])
    return jsonify(response), status_code

@routes.route('/edit_profile', methods=['PUT'])
def edit_profile():
    data = request.get_json()
    response, status_code = edit_patient_profile(data['email'], data)
    return jsonify(response), status_code

@routes.route('/patients', methods=['GET'])
def get_patients():
    response, status_code = get_all_patients()
    return jsonify(response), status_code
@routes.route('/doctors', methods=['GET'])
def get_doctors():
    response, status_code = get_all_doctors()
    return jsonify(response), status_code


@routes.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    response, status_code = send_password_reset_email(email)
    return jsonify(response), status_code

@routes.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_route(token):
    if request.method == 'GET':
        response, status_code = reset_password(token, 'GET')
    elif request.method == 'POST':
        data = request.get_json()
        response, status_code = reset_password(token, 'POST', data)
    return jsonify(response), status_code
@routes.route('/save_schedule', methods=['POST'])
def save_schedule_route():
    data = request.get_json()
    response, status_code = save_schedule(data)
    return jsonify(response), status_code
@routes.route('/get_schedule', methods=['GET'])
def get_schedule_route():
    email = request.args.get('email')
    response, status_code = get_schedule(email)
    return jsonify(response), status_code
@routes.route('/verify_id', methods=['GET'])
def verify_id_route():
    identification_number = request.args.get('identificationNumber')
    response, status_code = verify_id(identification_number)
    return jsonify(response), status_code
@routes.route('/register_admin', methods=['POST'])
def register_admin_route():
    data = request.get_json()
    response, status_code = register_admin(data)
    return jsonify(response), status_code
@routes.route('/get_patients', methods=['GET'])
def get_patients_route():
    query = request.args.get('query')
    response, status_code = get_patients(query)
    return jsonify(response), status_code

@routes.route('/get_doctors', methods=['GET'])
def get_doctors_route():
    query = request.args.get('query')
    response, status_code = get_doctors(query)
    return jsonify(response), status_code
@routes.route('/make_appointment', methods=['POST'])
def make_appointment_route():
    data = request.get_json()
    response, status_code = make_appointment(data)
    return jsonify(response), status_code
@routes.route('/get_appointments_for_doctor', methods=['GET'])
def get_appointments_for_doctor_route():
    email = request.args.get('email')
    response, status_code = get_appointments_for_doctor(email)
    return jsonify(response), status_code
@routes.route('/my_appointments', methods=['GET'])
def my_appointments_route():
    user_id = request.args.get('user_id')
    response, status_code = get_appointments_for_patient(user_id)
    return jsonify(response), status_code
@routes.route('/complete_appointment', methods=['POST'])
def complete_appointment_route():
    data = request.get_json()
    response, status_code = complete_appointment(data)
    return jsonify(response), status_code