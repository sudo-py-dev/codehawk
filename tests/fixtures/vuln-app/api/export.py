import pickle
import subprocess
import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route("/import", methods=["POST"])
def import_data():
    data = pickle.loads(request.data)
    return {"rows": len(data)}

@app.route("/preview")
def preview():
    url = request.args.get("url")
    r = requests.get(url)
    return r.text

@app.route("/config", methods=["POST"])
def config():
    cfg = yaml.load(request.data)
    return cfg

@app.route("/ping")
def ping():
    host = request.args.get("host")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
