from flask import Flask
from flask_smorest import Api
from flask_jwt_extended import JWTManager
from resources.user import blp as UserBlueprint
from db import db



def create_app(db_url=None):
    app = Flask(__name__)
    app.config["API_TITLE"] = "Stores REST API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///data.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = True
    db.init_app(app)

    app.config["JWT_SECRET_KEY"] = "23957113145696777562279572735455995478"

    api = Api(app)
    jwt = JWTManager(app)


    with app.app_context():
        db.create_all()


    api.register_blueprint(UserBlueprint)



    return app
