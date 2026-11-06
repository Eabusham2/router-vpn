"""Configured SS UoT authority; this metadata never establishes live readiness."""
import hashlib
import json
import re

IMAGE = 'ghcr.io/sagernet/sing-box:v1.13.12'
ASSET = 'routervpn-ss-service.json'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()

def pair(server_body, client_body):
    server, client = json.loads(server_body), json.loads(client_body)
    inbound = [v for v in server.get('inbounds', []) if v.get('tag') == 'ss-in']
    outbound = [v for v in client.get('outbounds', []) if v.get('tag') == 'proxy']
    if len(inbound) != 1 or len(outbound) != 1:
        raise ValueError('SS configured service has no unique source pair')
    incoming, outgoing = inbound[0], outbound[0]
    if set(incoming) != {'type','tag','listen','listen_port','method','password'} or incoming['type'] != 'shadowsocks' or incoming['listen'] != '::':
        raise ValueError('SS configured service differs from supported inbound')
    if set(outgoing) != {'type','tag','server','server_port','method','password'} or outgoing['type'] != 'shadowsocks' or outgoing['method'] != '2022-blake3-aes-256-gcm':
        raise ValueError('SS configured client differs from supported source')
    if not isinstance(outgoing['server'], str) or not outgoing['server'] or type(outgoing['server_port']) is not int or not 1 <= outgoing['server_port'] <= 65535:
        raise ValueError('SS configured endpoint is invalid')
    for a,b in (('listen_port','server_port'),('method','method'),('password','password')):
        if incoming[a] != outgoing[b]:
            raise ValueError('SS configured service and client do not match')
    if not isinstance(outgoing['password'], str) or not outgoing['password']:
        raise ValueError('SS configured credential is absent')
    return outgoing

def configured_service_image(compose_body):
    if not isinstance(compose_body, bytes) or len(compose_body) > 4 << 20:
        raise ValueError('configured service compose is invalid')
    source = compose_body.decode('utf-8')
    blocks = re.findall(r'(?ms)^  transports:\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)', source)
    if len(blocks) != 1:
        raise ValueError('configured transports service is not unique')
    images = re.findall(r'^    image: ([^\s]+)$', blocks[0], re.M)
    if len(images) != 1 or '$' in images[0] or len(images[0]) > 256:
        raise ValueError('configured transports image is not an exact literal')
    return images[0]

def declaration(server_body, client_body, image, configured_image):
    pair(server_body, client_body)
    if not isinstance(image, str) or not image or len(image) > 256:
        raise ValueError('SS configured image is invalid')
    if not isinstance(configured_image, str) or not configured_image or len(configured_image) > 256:
        raise ValueError('SS configured service image is invalid')
    return {'schema':1, 'configured_image':configured_image, 'generator_image':image, 'server_sha256':digest(server_body), 'source_sha256':digest(client_body)}

def capture(value, server_body, client_body, node, endpoint):
    if not isinstance(value,dict) or set(value) != {'schema','configured_image','generator_image','server_sha256','source_sha256'} or type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('SS configured capability declaration is malformed')
    if value != declaration(server_body, client_body, value['generator_image'], value['configured_image']):
        raise ValueError('SS configured capability source changed')
    if value['configured_image'] != IMAGE or value['generator_image'] != IMAGE:
        return None
    source = pair(server_body, client_body)
    if endpoint == '' and source['server'] == 'router.invalid':
        return None
    if not isinstance(node,str) or not re.fullmatch('[0-9a-f]{64}',node) or source['server'] != endpoint:
        raise ValueError('SS configured capability belongs to another paired node')
    return {'schema':1, 'node_id':node, 'configured_image':IMAGE, 'uot_version':2,
            'endpoint':endpoint, 'port':source['server_port'], 'method':source['method'],
            'key_sha256':digest(source['password'].encode()), 'source_sha256':digest(client_body)}
