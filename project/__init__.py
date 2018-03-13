from flask import Flask
from logger import init_microservice_logger
from services.services import configure_swagger

import project.apis.listeners
from project.configuration.views import configuration_blueprint
from project.health.views import health_blueprint


def create_app():
    app = Flask('management')

    from .rpc_example.views import rpc_blueprint as rpc_blueprint
    app.register_blueprint(rpc_blueprint)

    from .configuration.views import configuration_blueprint as configuration_blueprint
    app.register_blueprint(configuration_blueprint)

    from .health.views import health_blueprint as health_blueprint
    app.register_blueprint(health_blueprint)

    init_microservice_logger(app)
    configure_swagger(app)
    # project.apis.listeners.initialize_listeners()
    return app
