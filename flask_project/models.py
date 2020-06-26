from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

from . import db

groups = db.Table('groups',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

events = db.Table('events',
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    location = db.Column(db.String(50))
    date_joined = db.Column(db.DateTime)
    bio = db.Column(db.Text)
    password = db.Column(db.String(80))
    owned_group = db.relationship('Group', backref='owned_group')
    joined_group = db.relationship('Group', secondary=groups, lazy='subquery',
        backref=db.backref('joined_group', lazy=True))
    joined_event = db.relationship('Event', secondary=events, lazy='subquery',
        backref=db.backref('joined_event', lazy=True))
    comment = db.relationship('Comment', backref='user_comment', lazy=True)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    owner = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_created = db.Column(db.DateTime)
    description = db.Column(db.Text)
    joined_user = db.relationship('User', secondary=groups, lazy='subquery',
        backref=db.backref('joined_user_group', lazy=True))
    group_event = db.relationship('Event', backref='group_event')

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    location = db.Column(db.String(50))
    date = db.Column(db.DateTime)
    description = db.Column(db.Text)
    group = db.Column(db.Integer, db.ForeignKey('group.id'))
    joined_user = db.relationship('User', secondary=events, lazy='subquery',
        backref=db.backref('joined_user_event', lazy=True))
    comment = db.relationship('Comment', backref='event_comment', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(200), nullable=False)
    user = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    event = db.Column(db.Integer, db.ForeignKey('event.id'),
        nullable=False)

