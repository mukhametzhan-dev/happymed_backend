# insert_specializations.py
from models import db, Specialization
from app import create_app

specialties = [
    {"Spec_Id": 1, "Name": "Cardiologist"},
    {"Spec_Id": 2, "Name": "Neurologist"},
    {"Spec_Id": 3, "Name": "Orthopedic Surgeon"},
    {"Spec_Id": 4, "Name": "Dermatologist"},
    {"Spec_Id": 5, "Name": "Pediatrician"},
    {"Spec_Id": 6, "Name": "Oncologist"},
    {"Spec_Id": 7, "Name": "Endocrinologist"},
    {"Spec_Id": 8, "Name": "Gastroenterologist"},
    {"Spec_Id": 9, "Name": "Psychiatrist"},
    {"Spec_Id": 10, "Name": "Ophthalmologist"},
    {"Spec_Id": 11, "Name": "Urologist"},
    {"Spec_Id": 12, "Name": "Pulmonologist"},
    {"Spec_Id": 13, "Name": "Otolaryngologist (ENT Specialist)"},
    {"Spec_Id": 14, "Name": "Nephrologist"},
    {"Spec_Id": 15, "Name": "General Surgeon"},
    {"Spec_Id": 16, "Name": "Obstetrician-Gynecologist (OB-GYN)"},
    {"Spec_Id": 17, "Name": "Rheumatologist"},
    {"Spec_Id": 18, "Name": "Radiologist"},
    {"Spec_Id": 19, "Name": "Anesthesiologist"},
    {"Spec_Id": 20, "Name": "Pathologist"}
]

app = create_app()
with app.app_context():
    for specialty in specialties:
        spec = Specialization(Spec_Id=specialty["Spec_Id"], Name=specialty["Name"])
        db.session.add(spec)
    db.session.commit()
    print("Specializations inserted successfully.")