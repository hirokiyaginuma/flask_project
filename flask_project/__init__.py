import os

from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_sqlalchemy  import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='development',
        SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(app.instance_path, 'database.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS = False,
    )

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    bootstrap = Bootstrap(app)
    db.init_app(app)
    migrate.init_app(app, db)
    
    login_manager.init_app(app)
    login_manager.login_view = 'meetup.login'
    
    """
    with app.app_context():
        from . import meetup
        db.create_all()
    """
    
    @app.route('/')
    def index():
        return render_template('index.html')
    
    from . import meetup
    app.register_blueprint(meetup.bp)

    @app.cli.command("initdb")
    def reset_db():
        db.drop_all()
        db.create_all()

        print("Initialized databese")

    @app.cli.command("dropdb")
    def reset_db():
        db.drop_all()

        print("Dropped all tables in databese")

    return app