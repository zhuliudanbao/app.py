from flask import Flask, render_template, url_for, redirect,flash
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from forms import RegisterForm,LoginForm
import os

app = Flask(__name__)

class Config(object):
    SECRET_KEY = 'sadasdasdgdsggdagd'
    SQLALCHEMY_DATABASE_URI= os.getenv('DATABASE_URL','sqlite:///C:/Users/Administrator/PycharmProjects/app/venv/database.db')

app.config.from_object(Config)


bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message='You must login to access this page'
login_manager.login_message_category='info'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(20))



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))





@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if form.validate_on_submit():

        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password,form.password.data):
                login_user(user, remember=form.remember.data)
                flash('Login success',category='info')
                return redirect(url_for('dashboard'))

        flash('User not exit or password not match',category='danger')
        return redirect(url_for('login'))



    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])

def signup():
    form = RegisterForm()

    if form.validate_on_submit():

        hashed_password=generate_password_hash(form.password.data,method='sha256')
        new_user = User(username=form.username.data,
                        email=form.email.data,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()


        return render_template('pagejump.html')

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')


@app.route('/info')
def information():
    return render_template('information.html')


@app.route('/download', methods=['GET'])
def download():
    return render_template('downloaddata.html')


if __name__ == '__main__':
    app.run(debug=True)

