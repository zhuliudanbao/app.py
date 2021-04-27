from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,BooleanField
from wtforms.validators import InputRequired,Length,email,EqualTo


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=20)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=20)])
    confirm = PasswordField('repeat password',validators=[InputRequired(), EqualTo('password')])
