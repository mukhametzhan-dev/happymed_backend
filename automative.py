import random
from faker import Faker
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Doctor, User, Specialization  
from werkzeug.security import generate_password_hash


fake = Faker()
DATABASE_URL = "mysql+pymysql://root:11102017mA_@localhost/happy_db" 
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

specializations = list(range(1, 21))

def generate_schedule():
    """Generate a random schedule for a doctor."""
    days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
    schedule = []
    total_hours = 0

    while total_hours < 25:
        day = random.choice(days)
        start_hour = random.randint(6, 21) 
        end_hour = random.randint(start_hour + 1, min(start_hour + 4, 22)) 
        start_time = f"{start_hour:02}:00"
        end_time = f"{end_hour:02}:00"

        schedule.append({"day": day, "time": [start_time, end_time]})

        total_hours += end_hour - start_hour

        days.remove(day)
        if not days:
            break

    return schedule

def generate_phone_number():
    """Generate a random numeric phone number with up to 19 digits."""
    return "".join(random.choices("0123456789", k=random.randint(10, 19)))

export_data = []

for _ in range(10):
    first_name = fake.first_name()
    last_name = fake.last_name()
    email = fake.unique.email()
    phone = generate_phone_number()
    gender = random.choice(["Male", "Female"])
    spec_id = random.choice(specializations)
    schedule = generate_schedule()

    password = fake.password(length=12)
    hashed_password = generate_password_hash(password)  # Hash password for security

    doctor = Doctor(
        first_name=first_name,
        last_name=last_name,
        date_of_birth=fake.date_of_birth(minimum_age=30, maximum_age=60),
        email=email,
        phone=phone,
        gender=gender,
        spec_id=spec_id,
        schedule=schedule,
    )
    session.add(doctor)
    session.flush() 


    user = User(
        password=hashed_password,
        role="doctor",
        doctor_id=doctor.doctor_id,
    )
    session.add(user)
    session.commit()  


    export_data.append(f"{email}:{password}")

with open("doctors_credentials.txt", "w") as file:
    file.write("\n".join(export_data))

print("300 doctors added to the database, credentials saved to doctors_credentials.txt!")
