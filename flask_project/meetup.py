from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

from . import login_manager
from .models import db, User, Group

bp = Blueprint('meetup', __name__, url_prefix='/meetup')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

class GroupForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(max=50)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(max=500)])

@bp.route('/')
def index():
    return render_template('meetup/index.html')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        existing_username = User.query.filter_by(username=form.username.data).first()
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_username:
            flash("A user already exists with that username.")
        if existing_email:
            flash("A user already exists with that email address.")
        if existing_username is None and existing_email is None:
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            flash('New user has been created!')
            return redirect(url_for('meetup.group'))

    return render_template('meetup/register.html', form=form)
    
    
@bp.route('/login', methods=('GET', 'POST'))
def login():  
    form = LoginForm()
    error = None

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('meetup.group'))
        flash('Invalid username or password')
    
    return render_template('meetup/login.html', form=form)
   
@bp.route('/logout')
@login_required 
def logout():
    logout_user()
    flash('You have been successfully logged out.')
    return redirect(url_for('meetup.login'))
    
@bp.route('/group')
@login_required
def group():
    groups = db.session.query(Group)
    return render_template('meetup/group.html', name=current_user.username, groups=groups)

@bp.route('/group/addgroup', methods=('GET', 'POST'))
@login_required
def addgroup():
    form = GroupForm()

    if form.validate_on_submit():
        #existing_name = None
        existing_name = Group.query.filter_by(name=form.name.data).first()
        if existing_name:
            flash("A group already exists with that username.")
        if existing_name is None:
            new_group = Group(name=form.name.data, owner=current_user.id, 
                date_created=datetime.now(), description=form.description.data)
            db.session.add(new_group)
            new_group.joined_group.append(current_user)
            db.session.commit()

            flash('New group has been created!')
            return redirect(url_for('meetup.group'))

    return render_template('meetup/addgroup.html', form=form)