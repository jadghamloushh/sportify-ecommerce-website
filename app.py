from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_wtf import CSRFProtect
from flask import render_template

db = SQLAlchemy()

def create_app():
    app = Flask(__name__, template_folder='templates')
    csrf = CSRFProtect(app)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/jad/Desktop/Sportify-Website/testdb_backup.db'
    app.secret_key = 'Some Key'
    app.config['SECRET_KEY'] = 'tQa$L5Cu6^*yu"V'
    app.secret_key = app.config['SECRET_KEY']
    db.init_app(app)
    CORS(app, supports_credentials=True)
    login_manager = LoginManager()
    login_manager.init_app(app)
    secret_key = app.secret_key
    bcrypt = Bcrypt(app)

    from models import User

    @login_manager.user_loader
    def load_user(uid):
        return User.query.get(uid)

    bcrypt = Bcrypt(app)

    from routes import register_routes
    register_routes(app, db, bcrypt)

    migrate = Migrate(app, db)

    return app