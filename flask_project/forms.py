from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, DateField, validators
from wtforms.validators import InputRequired, Email, Length

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    location = StringField('Location', validators=[InputRequired(), Length(max=50)])
    bio = TextAreaField('bio', validators=[InputRequired(), Length(max=500)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80), 
        validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')

class GroupForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(max=50)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(max=500)])

class EventForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(max=50)])
    date = DateField('Date')
    location = StringField('Location', validators=[InputRequired(), Length(max=50)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(max=500)])