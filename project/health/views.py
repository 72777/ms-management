import os

from flask import Blueprint
from flask_restplus import Api, Namespace, Resource
from flask.logging import getLogger

health_blueprint = Blueprint('health', __name__)
health_api = Api(health_blueprint)
health_namespace = Namespace(name='health', path='/', description='Authentication API')
health_api.add_namespace(health_namespace)


@health_namespace.route('/health')
class health(Resource):
    def get(self):
        """Get service health"""
        script_path = os.path.dirname(os.path.abspath(__file__))
        with open(script_path + '/../VERSION', 'r') as f:
            VERSION = f.read().strip()
        getLogger('management').debug('Version: %s' % VERSION)
        return {"version": VERSION}
