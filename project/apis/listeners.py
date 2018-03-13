import os

from flask import json
from flask.logging import getLogger

from messaging.fctn import FactionTopicConsumer, FactionFanoutConsumer, FactionRPCServer

logger = getLogger('management')


def initialize_listeners():
    rpc_consumer = FactionRPCServer(os.getenv('RABBIT_HOST'),
                                    queue='rpc_queue')
    rpc_consumer.start()

    app_topic_consumer = FactionTopicConsumer(os.getenv('RABBIT_HOST'),
                                              exchange='app_topic',
                                              routing_key='config.#',
                                              callback_func=app_topic_handle_message)
    app_topic_consumer.initialize_exchange()
    app_topic_consumer.start()

    app_fanout_consumer = FactionFanoutConsumer(os.getenv('RABBIT_HOST'),
                                                exchange='app_fanout',
                                                callback_func=app_fanout_handle_message)
    app_fanout_consumer.initialize_exchange()
    app_fanout_consumer.start()

    cmdb_topic_consumer = FactionTopicConsumer(os.getenv('RABBIT_HOST'),
                                               exchange='cmdb',
                                               durable=True,
                                               routing_key='cmdb.#',
                                               callback_func=cmdb_topic_handle_message)
    cmdb_topic_consumer.initialize_exchange()
    cmdb_topic_consumer.start()


def app_fanout_handle_message(ch, method, properties, body):
    logger.debug('Received amqp message: exchange=%s, routing_key=%s, delivery_tag=%s, redelivered=%s, body=%s' %
                 (method.exchange, method.routing_key, method.delivery_tag, method.redelivered, body))
    msg = json.loads(body)
    if msg.get('to', None) in ['management', 'all']:
        if msg['property'] == 'loglevel':
            getLogger('management').setLevel(msg['value'].upper())


def app_topic_handle_message(ch, method, properties, body):
    logger.debug('Received amqp message: exchange=%s, routing_key=%s, delivery_tag=%s, redelivered=%s, body=%s' %
                 (method.exchange, method.routing_key, method.delivery_tag, method.redelivered, body))
    msg = json.loads(body)
    if msg.get('to', None) in ['management', 'all']:
        if msg['property'] == 'loglevel':
            getLogger('management').setLevel(msg['value'].upper())


def cmdb_topic_handle_message(cm, method, properties, body):
    logger.debug('Received amqp message: exchange=%s, routing_key=%s, delivery_tag=%s, redelivered=%s, body=%s' %
                 (method.exchange, method.routing_key, method.delivery_tag, method.redelivered, body))
