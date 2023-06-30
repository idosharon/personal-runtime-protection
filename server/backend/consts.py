from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from flask_socketio import SocketIO
from engineio.payload import Payload
from Crypto.Cipher import AES

# config app
Payload.max_decode_packets = 5000
app = Flask(__name__)
sio = SocketIO(app)

# config db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.sqlite')
db = SQLAlchemy(app)

@app.after_request
def handle_options(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"

    return response

# config consts
consts = {
    "OPENAI_API_KEY": os.environ["OPENAI_API_KEY"],
    "AES_KEY": os.environ["AES_KEY"]
}

# config statistics
statistics = {}

# clients
clients = []

# create AES cipher
cipher = AES.new(consts["AES_KEY"].encode("utf-8"), AES.MODE_CBC)

