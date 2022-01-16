from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import pyotp
import subprocess, sys
import qrcode
from PIL import Image  
import PIL  


app = Flask(__name__)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

bcrypt = Bcrypt(app)


def parse_arg_from_requests(arg, **kwargs):
    parse = reqparse.RequestParser()
    parse.add_argument(arg, **kwargs)
    args = parse.parse_args()
    return args[arg]

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(20), nullable=False, unique=True)
    sec_key = db.Column(db.String(20), nullable=False, unique=True)


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min = 1, max=20)], render_kw={"placeholder":"Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min = 1, max=20)], render_kw={"placeholder":"Password"})

    otp = StringField(validators=[InputRequired()], render_kw={"placeholder":"otp"})
    
    submit = SubmitField("Login")


class AddUserForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min = 1, max=20)], render_kw={"placeholder":"Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min = 1, max=80)], render_kw={"placeholder":"Password"})

    email = StringField(validators=[InputRequired(), Length(
        min = 1, max=20)], render_kw={"placeholder":"email"})

    submit = SubmitField("AddUser")
    
    def validate_username(self,username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        
        if existing_user_username:
            raise ValidationError("User already exists")


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    
    #return render_template("login.html", secret=secret, form = form)
    print('Form initialized')

    otp = request.values.get("otp")
    print("otp:", otp)

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user:
            if bcrypt.check_password_hash(user.password, form.password.data) and pyotp.TOTP(user.sec_key).verify(otp):
                login_user(user)
                return redirect(url_for('dashboard'))
    else:
        print('Not validated')
    return render_template('login.html', form=form)


@app.route('/adduser', methods=['GET', 'POST'])
#@login_required
def adduser():
    form = AddUserForm()
    secret=pyotp.random_base32()
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, sec_key = secret)
        db.session.add(new_user)
        db.session.commit()
        
        #generate qr code
        sec_key_generated = pyotp.totp.TOTP(secret).provisioning_uri(form.email.data, issuer_name=form.username.data)
        qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
        )
        qr.add_data(sec_key_generated)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        image.save("qrcode.png")

        return (url_for('login'))
        
    return render_template('adduser.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    p = subprocess.Popen(["powershell.exe", 
    "C:\\Users\\Leo\\Documents\\GitHub\\UserLogin\\mkdir.ps1"], 
    stdout=sys.stdout)
    p.communicate()
    
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)