from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from dotenv import load_dotenv
import os


# Load environment variables from .env
load_dotenv()
secrets_key = os.environ.get('SECRET_KEY')
database_url = os.environ.get('DATABASE_URI')

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets_key

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
db = SQLAlchemy()
db.init_app(app)


# create login manager
login_manager = LoginManager()
# configure it for login
login_manager.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
 

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer)
    product_name = db.Column(db.String(200))


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return render_template("secrets.html", name=new_user.name)
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    # Retrieve user from the database based on the provided email
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        # Password is correct
        flash('Login successful!', 'success')
        login_user(user)
        return render_template('secrets.html', email=email, name=user.name)
    else:
        # Invalid credentials
        flash('Login failed. Check your email and password.', 'danger')

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
