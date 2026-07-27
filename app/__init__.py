from flask import Flask

from app.config import Config
from app.database import initialize_database


def create_app():

    app = Flask(__name__)
    app.config.from_object(Config)

    initialize_database()

    from app.routes.home import home
    from app.routes.url import url
    from app.routes.history import history
    from app.routes.dashboard import dashboard

    app.register_blueprint(home)
    app.register_blueprint(url)
    app.register_blueprint(history)
    app.register_blueprint(dashboard)

    return app