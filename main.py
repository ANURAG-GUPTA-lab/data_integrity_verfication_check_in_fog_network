from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
import json
import subprocess
import time
import matplotlib.pyplot as plt
import threading
import os
from base64 import b64encode, b64decode


app = Flask(__name__)

# Global variables for key pair and processing times
private_key, public_key = None, None
processing_times = []
security_hash_levels = []

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA512())
    )
    return b64encode(signature).decode('utf-8')

def verify_signature(public_key, data, signature):
    public_key.verify(
        b64decode(signature),
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA512())
    )

def process_data(data, private_key, public_key):
    start_time = time.time()

    # Convert data to JSON
    data_json = json.dumps(data, sort_keys=True).encode('utf-8')

    # Calculate SHA-512 hash
    hash_value = hashes.Hash(hashes.SHA512(), backend=default_backend())
    hash_value.update(data_json)
    calculated_hash = hash_value.finalize()

    # Sign the hash with the private key
    signature = sign_data(private_key, calculated_hash)

    # Verify the signature using the public key
    verify_signature(public_key, calculated_hash, signature)

    end_time = time.time()

    # Append processing time to the global list
    processing_times.append(end_time - start_time)
    security_hash_levels.append(calculated_hash)

    return jsonify({
        'message': 'Data integrity verified: No tampering detected.',
        'signature': signature,
        'processing_time': end_time - start_time,
        'security_hash_level': b64encode(calculated_hash).decode('utf-8')
    }), end_time - start_time

@app.route('/process_data', methods=['POST'])
def process_data_route():
    data = request.get_json()
    response, _ = process_data(data, private_key, public_key)
    return response, 200

@app.route('/plot_performance_graph', methods=['GET'])
def plot_performance_graph():
    if not security_hash_levels:
        return jsonify({'message': 'No data available for plotting.'}), 400

    # Plot performance graph
    plt.plot(processing_times)
    plt.xlabel('Request Number')
    plt.ylabel('Processing Time (seconds)')
    plt.title('Performance Graph: Data Integrity Verification')

    # Save the performance graph as a PNG file
    performance_graph_file = 'performance_graph.png'
    plt.savefig(performance_graph_file, format='png', dpi=300, bbox_inches='tight', pad_inches=0, transparent=True)

    # Close the plot to avoid displaying it
    plt.close()

    # Plot security hash level metrics
    plt.plot(range(len(security_hash_levels)), [hash_level.decode('latin-1') for hash_level in security_hash_levels], marker='o', linestyle='', markersize=5)
    plt.xlabel('Request Number')
    plt.ylabel('Security Hash Level Metrics')
    plt.title('Security Hash Level Metrics Graph')

    # Save the security hash level metrics graph as a PNG file
    hash_metrics_graph_file = 'hash_metrics_graph.png'
    plt.savefig(hash_metrics_graph_file, format='png', dpi=300, bbox_inches='tight', pad_inches=0, transparent=True)

    # Close the plot to avoid displaying it
    plt.close()

    return jsonify({
        'message': 'Performance and security hash level metrics graphs saved.',
        'performance_graph_file': performance_graph_file,
        'hash_metrics_graph_file': hash_metrics_graph_file
    }), 200



def run_flask_app():
    # Generate key pair
    global private_key, public_key
    private_key, public_key = generate_key_pair()

    # Run Flask app
    app.run(port=5000)

if __name__ == "__main__":
    # Start Flask app in a separate thread
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.start()

    # Wait for the Flask app to start
    time.sleep(2)

    # Make a curl request
    #response = os.popen('curl -X POST -H "Content-Type: application/json" --data @data.json http://127.0.0.1:5000/process_data').read()
    #print(response)
    # List of data files to process
    data_files = [f'data_instance_{i}.json' for i in range(1, 151)]  # Adjust the range based on the number of instances

    for data_file in data_files:
        with open(data_file, 'r') as file:
            data = json.load(file)
        
        # Make an HTTP POST request for each data file
        response = requests.post('http://127.0.0.1:5000/process_data', json=data, headers={'Content-Type': 'application/json'})
        
        # Print the response content
        print(response.text)

    # Plot the graphs
    app_client = app.test_client()
    app_client.get('/plot_performance_graph')

    # Join the Flask thread
    flask_thread.join()
