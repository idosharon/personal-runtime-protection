import flask

app = flask.Flask(__name__)


@app.route("/")
def home():
    return "Hello, World!"


# create api route for the client to send data to
@app.route("/api/", methods=["POST"])
def api():
    data = flask.request.json
    print(data)
    return "OK"
