"""
    File: app.py
    Description: Backend server for the application.
        It is responsible for:
        - saving events to the database
        - serving the API
        - receiving the socket io events
"""

from .consts import app, db, sio, statistics, cipher, clients
from .models import *
from flask import jsonify, request
from .utils import ask_chatgpt
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import unpad

@app.route('/', methods=['GET'])
def index():
    return "Ok"

# socket io events
@sio.on('connect')
def connect():
    print('Client connected', request.sid)
    clients.append(request.sid)

@sio.on('event')
def save_event(event):
    try:
        # decode event
        event = b64decode(event)
        # decrypt event
        event = unpad(cipher.decrypt(event), AES.block_size)
        event = event.decode("utf-8")

        # prase data to event
        parsed_event = json.loads(event)
        event_data = parsed_event['data']
        syscall = parsed_event['syscall']
        event = Event(event_data["ts"], syscall, event_data["pid"], event_data["ppid"], \
                    event_data["uid"], event_data["process"], event_data["value"])
        db.session.add(event)
        db.session.commit()

        statistics[syscall] = statistics.get(syscall, 0) + 1
    except Exception as e:
        print("Failed to save event: ", e)

@sio.on('disconnect')
def disconnect():
    print('Client disconnected', request.sid)
    clients.remove(request.sid)

# api endpoints
@app.route('/api/clients', methods=['GET'])
def get_clients():
    return jsonify(clients)

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    return jsonify(statistics)

# api endpoints
@app.route('/api/events/add', methods=['POST'])
def add_event():
    data = request.get_json()
    event = Event(data['timestamp'], data['syscall'], data['pid'], data['ppid'], data['uid'], data['process'], data['value'])
    db.session.add(event)
    db.session.commit()
    return jsonify(event.serialize())

@app.route('/api/events', methods=['GET'])
def get_events():
    events = Event.query.all()
    return jsonify([e.serialize() for e in events])

@app.route('/api/rules/add', methods=['POST'])
def add_rule():
    data = request.get_json()
    rule = Rule(data['title'], data['description'], data['code'], data['level'], data['sql_code'])
    db.session.add(rule)
    db.session.commit()
    return jsonify(rule.serialize())

@app.route('/api/rules/delete', methods=['DELETE'])
def delete_rule():
    data = request.get_json()
    rule = Rule.query.get(data['id'])
    db.session.delete(rule)
    db.session.commit()
    return jsonify(rule.serialize())

@app.route('/api/rules', methods=['GET'])
def get_rules():
    rules = Rule.query.all()
    return jsonify([r.serialize() for r in rules])

@app.route('/api/scan', methods=['GET'])
def scan():
    rules = Rule.query.all()
    found_events = {}
    for rule in rules:
        for e in Event.query.from_statement(text(rule.sql_code)).all():
            key = f"{e.process} {e.value} ({e.syscall})".strip()
            if key in found_events:
                found_events[key].append(e.serialize())
            else:
                found_events[key] = [e.serialize()]
    return jsonify(found_events)

@app.route('/api/explain', methods=['GET', 'POST'])
def explain():
    data = request.get_json()
    event_id = data.get("event_id", None)
    if event_id is None:
        return jsonify({"error": "event id not found"})
    print(event_id)
    event = Event.query.get(event_id)
    if event is None:
        return jsonify({"error": "event not found"})
    response = ask_chatgpt(event)
    json_response = jsonify(response)
    if json_response.is_json and all(key in json_response.json for key in ["event", "suspicious", "reason", "process", "action"]):
        return json_response
    return jsonify({"error": "response error"})

from Crypto.PublicKey import RSA
@app.route('/api/public-key', methods=['GET'])
def get_public_key():
    rsa_public_key = request.args.get("pem", None)
    if rsa_public_key is None:
        return jsonify({"error": "public key not found"})
    rsa_public_key = b64decode(rsa_public_key)

    aes_key = open("aes_key.txt", "r").read()

    # encrypt aes key with rsa public key which is in pem format
    rsa_public_key = RSA.importKey(rsa_public_key)
    encryptor = PKCS1_OAEP.new(rsa_public_key)
    return jsonify({
        "aes_key": b64encode(encryptor.encrypt(aes_key.encode("utf-8"))).decode("utf-8")
    })

with app.app_context():
    db.create_all()
    for e in Event.query.all():
        statistics[e.syscall] = statistics.get(e.syscall, 0) + 1

if __name__ == "__main__":
    db.create_all()
    sio.run(app, debug=False)
