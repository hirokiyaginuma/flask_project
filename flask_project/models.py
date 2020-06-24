from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

from . import db

groups = db.Table('groups',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    owned_group = db.relationship('Group', backref='owned_group')
    joined_group = db.relationship('Group', secondary=groups, lazy='subquery',
        backref=db.backref('joined_group', lazy=True))

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    owner = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_created = db.Column(db.DateTime)
    description = db.Column(db.Text)
    joined_user = db.relationship('User', secondary=groups, lazy='subquery',
        backref=db.backref('joined_user', lazy=True))