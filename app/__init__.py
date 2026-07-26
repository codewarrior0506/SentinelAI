from flask import Flask

def create_app():

    app = Flask(__name__)

    from app.routes.home import home
    from app.routes.url import url

    app.register_blueprint(home)
    app.register_blueprint(url)

    return app