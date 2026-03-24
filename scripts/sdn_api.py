from flask import Flask, jsonify, request
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route('/stats/switches', methods=['GET'])
def get_switches():
    # Return a simulated switch for Sentinel dashboard/backend checks
    return jsonify(["1"])

@app.route('/stats/flowentry/add', methods=['POST'])
def add_flow():
    # Simulate success for flow blocking requests from C backend
    data = request.get_json()
    app.logger.info(f"SDN Rule Add Request: {data}")
    return "success", 200

@app.route('/stats/flow/<dpid>', methods=['GET'])
def get_flows(dpid):
    return jsonify({str(dpid): []})

if __name__ == '__main__':
    # Standard Ryu/OS-Ken port
    app.run(host='0.0.0.0', port=8080)
