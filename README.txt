PROJECT: The Meetup! Website

FILES:
.
├── MANIFEST.in
├── README.txt
├── flask_project
│   ├── __init__.py
│   ├── __pycache__
│   ├── forms.py
│   ├── meetup.py
│   ├── models.py
│   ├── static
│   │   └── style.css
│   └── templates
│       ├── base.html
│       ├── index.html
│       └── meetup
│           ├── addevent.html
│           ├── addgroup.html
│           ├── detail.html
│           ├── event.html
│           ├── eventdetail.html
│           ├── group.html
│           ├── index.html
│           ├── login.html
│           ├── profile.html
│           └── register.html
├── flask_project.egg-info
├── instance
│   └── database.db
├── migrations
├── myvenv
├── setup.py
└── sqlite3.exe

DESCRIPTION:
The goal of this project is to implement the meetup website on flask application.
In this webpage, the user can register with their unique email address and password.
Once the user logged in, they can create groups and events, or check their profiles.
In group detail view and event detail view, the user can check detailed information about
the group/event and join the group/event.
In event detail view, the user can leave comments to the event.