from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, validators
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

from . import login_manager
from .models import db, User, Group, Event

bp = Blueprint('meetup', __name__, url_prefix='/meetup')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@bp.context_processor
def inject_user():
    return dict(isloggedin=current_user.is_authenticated)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80), 
        validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')

class GroupForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(max=50)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(max=500)])

class EventForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(max=50)])
    location = StringField('Location', validators=[InputRequired(), Length(max=50)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(max=500)])

@bp.route('/')
def index():
    return render_template('meetup/index.html')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    form = RegisterForm()

    if current_user.is_authenticated:
        flash('You are already logged in.')
        return redirect(url_for('meetup.group'))

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

    if current_user.is_authenticated:
        flash('You are already logged in.')
        return redirect(url_for('meetup.group'))
        

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
        existing_name = Group.query.filter_by(name=form.name.data).first()
        if existing_name:
            flash("A group already exists with that name.")
        if existing_name is None:
            new_group = Group(name=form.name.data, owner=current_user.id, 
                date_created=datetime.now(), description=form.description.data)
            db.session.add(new_group)
            new_group.joined_user.append(current_user)
            db.session.commit()

            flash('New group has been created!')
            return redirect(url_for('meetup.group'))

    return render_template('meetup/addgroup.html', form=form)

@bp.route('/group/<int:group_id>')
@login_required
def group_detail(group_id):
    group = Group.query.filter_by(id=group_id).one()
    owner = User.query.filter_by(id=group.owner).first()

    return render_template('meetup/detail.html', group=group, owner=owner)

@bp.route('/group/<int:group_id>/event')
@login_required
def event(group_id):
    group = Group.query.filter_by(id=group_id).one()

    if not (current_user in group.joined_user):
        flash('You have to join the group to see events.')
        return redirect(url_for('meetup.group_detail', group_id=group_id))

    return render_template('meetup/event.html', group=group)


@bp.route('/group/<int:group_id>/event/addevent', methods=('GET', 'POST'))
@login_required
def addevent(group_id):
    form = EventForm()
    group = Group.query.filter_by(id=group_id).one()

    if not (current_user in group.joined_user):
        flash('You have to join the group to see events.')
        return redirect(url_for('meetup.group_detail', group_id=group_id))

    if form.validate_on_submit():
        new_event = Event(name=form.name.data, group=group.id, location=form.location.data, 
            description=form.description.data)
        db.session.add(new_event)
        new_event.joined_user.append(current_user)
        db.session.commit()

        flash('New event has been created!')
        return redirect(url_for('meetup.event', group_id=group_id))

    return render_template('meetup/addevent.html', group=group, form=form)

@bp.route('/group/<int:group_id>/event/<int:event_id>')
@login_required
def event_detail(group_id, event_id):
    group = Group.query.filter_by(id=group_id).one()
    event = Event.query.filter_by(id=event_id).one()
    
    if not (current_user in group.joined_user):
        flash('You have to join the group to see events.')
        return redirect(url_for('meetup.group_detail', group_id=group_id))

    return render_template('meetup/eventdetail.html', group=group, event=event)

@bp.route('/api/joingroup/<int:group_id>')
@login_required
def joingroup(group_id):
    group = Group.query.filter_by(id=group_id).one()

    if current_user in group.joined_user:
        flash('You are already in the group.')
        return redirect(url_for('meetup.group_detail', group_id=group_id))

    group.joined_user.append(current_user)
    db.session.commit()
    flash('You have joined this group!')

    return redirect(url_for('meetup.group_detail', group_id=group_id))

@bp.route('/api/joingroup/<int:group_id>/<int:event_id>')
@login_required
def joinevent(group_id, event_id):
    group = Group.query.filter_by(id=group_id).one()
    event = Event.query.filter_by(id=event_id).one()

    if current_user in event.joined_user:
        flash('You are already in the event.')
        return redirect(url_for('meetup.event_detail', group_id=group_id, event_id=event_id))

    event.joined_user.append(current_user)
    db.session.commit()
    flash('You have joined this group!')

    return redirect(url_for('meetup.event_detail', group_id=group_id, event_id=event_id))
