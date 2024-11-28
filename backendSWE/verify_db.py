
from models import db, Specialization
from app import create_app

app = create_app()
with app.app_context():
    specializations = Specialization.query.all()
    for spec in specializations:
        print(f"{spec.Spec_Id}: {spec.Name}")