import os

from flask import Blueprint
from flask.logging import getLogger
from flask_restplus import Api, Namespace, Resource, fields

from messaging.fctn import FactionFanoutProducer

logger = getLogger('management')

configuration_blueprint = Blueprint('configuration', __name__, url_prefix='/app')
configuration_api = Api(configuration_blueprint)
configuration_namespace = Namespace(name='configuration', path='/', description='Configuration API')
configuration_api.add_namespace(configuration_namespace)

configuration_model = configuration_api.model('Configuration', {
    'to': fields.String(required=True, description='Service (all for all)'),
    'category': fields.String(required=True, enum=['config'], description='Type of change'),
    'property': fields.String(required=True, description='Property to change'),
    'value': fields.String(required=True, description='Value to set')
})

fanout_producer = FactionFanoutProducer(os.getenv('RABBIT_HOST'), exchange='app_fanout')
fanout_producer.initialize_exchange()


@configuration_namespace.route('/configuration')
class Configuration(Resource):
    @configuration_namespace.expect(configuration_model)
    @configuration_namespace.marshal_with(configuration_model, code=201)
    def post(self):
        data = configuration_api.payload
        success = fanout_producer.basic_publish(data)
        if not success:
            msg = 'Failed to send error to via message bus'
            logger.critical(msg)
            return msg, 503
        return data, 201
