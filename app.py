# app.py
from flask import Flask
from flask_migrate import Migrate
from flask_cors import CORS
from config import Config
from models import db
from routes import routes

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)
    db.init_app(app)
    
    migrate = Migrate(app, db)

    app.register_blueprint(routes)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, use_reloader=True)
