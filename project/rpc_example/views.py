import os

from flask import Blueprint
from flask.logging import getLogger
from flask_restplus import Api, Namespace, Resource, fields

from messaging.fctn import FactionRPCProducer

logger = getLogger('management')

rpc_blueprint = Blueprint('rpc', __name__, url_prefix='/rpc')
rpc_api = Api(rpc_blueprint)
rpc_namespace = Namespace(name='rpc', path='/', description='RPC example API')
rpc_api.add_namespace(rpc_namespace)

rpc_model = rpc_api.model('Rpc', {
    'string': fields.String(required=True, description='Any string')
})

rpc_client = FactionRPCProducer(os.getenv('RABBIT_HOST'), queue='rpc_queue')


@rpc_namespace.route('/example')
class Rpc(Resource):
    @rpc_namespace.expect(rpc_model)
    @rpc_namespace.marshal_with(rpc_model, code=201)
    def post(self):
        logger.debug('RPC Request: %s' % rpc_api.payload)
        data = rpc_api.payload
        response = rpc_client.call(data)
        logger.debug('RPC Response: %s' % response)

        return response, 200
