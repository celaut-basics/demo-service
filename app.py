#!/usr/bin/env python3.11

import os, logging, requests
from flask import Flask, jsonify, request, render_template_string
from google.protobuf.json_format import MessageToDict

from node_controller.controller.controller import Controller

DIR = "service"

env_vars = {}
with open(os.path.join(DIR, ".dependencies")) as f:
    for line in f:
        key, value = line.strip().split("=")
        env_vars[key] = value

TINY_SERVICE = env_vars.get("TINY", None)  # From .dependencies TINY

logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Create a new Flask app
app = Flask(__name__)

# Read the service configuration file. The service configuration file is written by the node when it builds the container and contains information such as the initial resources or the node URL.
controller = Controller()
node_url: str = controller.get_node_url()
mem_limit: int = controller.get_mem_limit_at_start()

# Set values
resources = {
    "mem_limit": mem_limit
}
gas_amount = 0
tiny_service = controller.add_service(service_hash=TINY_SERVICE)  # Generates the instance obj on the library. It will start instances, stop and check if they are alive in background.
services = []
logging.info('Gateway main directory: %s', node_url)

# HTML template for the page
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo Service</title>
    <link rel="stylesheet" href="https://unpkg.com/papercss@1.9.2/dist/paper.min.css">
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 1200px; margin: auto; }
        .flex-container {
            display: flex;
            justify-content: space-between;
            gap: 20px;
        }
        .card { 
            flex: 1;
            margin: 10px;
            padding: 20px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
        th { background-color: #f4f4f4; }
    </style>
</head>
<body>
    <div>
        <h1>Celaut node interaction demo</h1>
        
        <div class="flex-container">
            <!-- Card 1: Gas and Memory -->
            <div class="card">
                <h2>Resource Management</h2>
                <div id="gasDisplay">Gas Amount: Loading...</div>
                <div id="memoryDisplay">Memory Used: Loading...</div>
                <div id="adjustmentDisplay">Memory Adjustment: 0 MB</div>
                <button class="btn btn-primary" onclick="adjustMemory(10)">Increase Memory Limit</button>
                <button class="btn btn-secondary" onclick="adjustMemory(-10)">Decrease Memory Limit</button>
                <button class="btn btn-danger" onclick="sendAdjustment()">Send</button>
            </div>

            <!-- Card 2: Services Table -->
            <div class="card">
                <h2>Services</h2>
                <button class="btn btn-success" onclick="generateService()">Generate New Service</button>
                <button class="btn btn-primary" onclick="useServices()">Use Services</button>
                <table>
                    <thead>
                        <tr>
                            <th>IP:Port</th>
                            <th>Result</th>
                        </tr>
                    </thead>
                    <tbody id="servicesTable">
                        <!-- Service rows will be dynamically added here -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let memoryAdjustment = 0;

        async function updateDisplay() {
            try {
                const memoryResponse = await fetch('/memory_usage');
                const memoryData = await memoryResponse.json();
                document.getElementById('memoryDisplay').innerText = 'Memory Used: ' + memoryData.memory_used + ' MB';
                
                const gasResponse = await fetch('/current_gas');
                const gasData = await gasResponse.json();
                document.getElementById('gasDisplay').innerText = 'Gas Amount: ' + gasData.gas_amount;

                return memoryData.memory_used;
            } catch (error) {
                console.error('Error updating display:', error);
            }
        }

        function adjustMemory(amount) {
            memoryAdjustment += amount;
            document.getElementById('adjustmentDisplay').innerText = 'Memory Adjustment: ' + memoryAdjustment + ' MB';
            console.log('Memory adjustment set to', memoryAdjustment);
        }

        async function sendAdjustment() {
            try {
                const currentMemory = await updateDisplay();
                const newMemoryLimit = parseFloat(currentMemory) + memoryAdjustment;

                const response = await fetch('/modify_max_memory', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ max_mem_limit: newMemoryLimit })
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error('Server error: ' + errorText);
                }

                const result = await response.json();
                console.log('Server response:', result);

                memoryAdjustment = 0;
                document.getElementById('adjustmentDisplay').innerText = 'Memory Adjustment: 0 MB';
                updateDisplay();
            } catch (error) {
                console.error('Error sending adjustment:', error);
            }
        }

        async function loadServices() {
            try {
                const response = await fetch('/services');
                const servicesData = await response.json();
                
                const servicesTable = document.getElementById('servicesTable');
                servicesTable.innerHTML = '';

                servicesData.forEach(service => {
                    const row = document.createElement('tr');
                    row.innerHTML = `<td>${service.ip_port}</td><td>${service.result}</td>`;
                    servicesTable.appendChild(row);
                });
            } catch (error) {
                console.error('Error loading services:', error);
            }
        }

        async function generateService() {
            try {
                const response = await fetch('/generate_service', {
                    method: 'POST'
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error('Server error: ' + errorText);
                }

                const result = await response.json();
                console.log('New service generated:', result);

                loadServices();
            } catch (error) {
                console.error('Error generating service:', error);
            }
        }
        
        async function useServices() {
            try {
                const response = await fetch('/use_services', {
                    method: 'POST'
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error('Server error: ' + errorText);
                }

                const result = await response.json();
                console.log('Services used:', result);

                loadServices();  // Reload the services to update their results.
            } catch (error) {
                console.error('Error using services:', error);
            }
        }

        updateDisplay();
        loadServices();
    </script>
</body>
</html>
"""

# Define the home route to serve the HTML page
@app.route('/')
def home():
    logging.info('Serving the home page.')
    return render_template_string(HTML_TEMPLATE)

# Endpoint to modify memory limit
@app.route('/modify_max_memory', methods=['POST'])
def modify_mem_limit():
    try:
        max_mem_limit = request.json.get('max_mem_limit')
        logging.info('Memory limit updating to %s', max_mem_limit)
        if max_mem_limit is None:
            logging.warning('Received request without max_mem_limit.')
            return jsonify({"error": "Missing 'max_mem_limit' in request body"}), 400
        
        max_mem_limit = int(max_mem_limit * (1024 * 1024))

        _resources, _gas_amount = controller.modify_resources(
            resources={'max': max_mem_limit, 'min': 0}
        )
        
        _resources = MessageToDict(_resources)
        global resources, gas_amount
        resources = {
            "mem_limit": int(_resources["memLimit"])
        }
        gas_amount = int(_gas_amount)
        
        logging.info('Memory limit updated to %s', resources['mem_limit'])
        return jsonify({"status": "Memory limit updated"})
    except Exception as e:
        logging.error('Error while modifying memory limit: %s', str(e))
        return jsonify({"error": str(e)}), 500

# Endpoint to retrieve services data
@app.route('/services', methods=['GET'])
def get_services():
    return jsonify([{"ip_port": service[0], "result": service[1]} for service in services])

# Endpoint to generate a new service
@app.route('/generate_service', methods=['POST'])
def generate_service():
    try:
        service_uri = tiny_service.get_instance().uri

        new_service = (service_uri, "--")
        services.append(new_service)
        logging.info('Generated new service: %s', new_service)
        return jsonify({"status": "Service generated", "service": new_service})
    except Exception as e:
        logging.error('Error while generating service: %s', str(e))
        return jsonify({"error": str(e)}), 500
    
@app.route('/use_services', methods=['POST'])
def use_services():
    try:
        for idx, service in enumerate(services):
            ip_port = service[0]
            try:
                response = requests.get(f"http://{ip_port}")
                result = response.text  # Extract the text from the response.
            except requests.exceptions.RequestException as e:
                logging.error('Error contacting service at %s: %s', ip_port, str(e))
                result = 'Error'

            # Update the result in the services list.
            services[idx] = (ip_port, result)
            logging.info('Updated service result for %s: %s', ip_port, result)
        
        return jsonify({"status": "Services used successfully", "services": services})
    except Exception as e:
        logging.error('Error while using services: %s', str(e))
        return jsonify({"error": str(e)}), 500

# Endpoint to view the current gas amount in scientific notation
@app.route('/current_gas', methods=['GET'])
def current_gas():
    gas_scientific = "{:.2e}".format(gas_amount)
    logging.info('Current gas amount: %s', gas_scientific)
    return jsonify({"gas_amount": gas_scientific})

# Endpoint to view memory usage (in MB, avoiding long zero sequences)
@app.route('/memory_usage', methods=['GET'])
def memory_usage():
    memory_used_bytes = resources.get('mem_limit', 0)
    memory_used_mb = memory_used_bytes / (1024 * 1024) if memory_used_bytes else 0
    memory_used_formatted = "{:.2f}".format(memory_used_mb)
    logging.info('Current memory usage: %s MB', memory_used_formatted)
    return jsonify({"memory_used": memory_used_formatted})

# Run the app on the local server
if __name__ == '__main__':
    logging.info('Starting the Flask application.')
    app.run(host='0.0.0.0', port=5000, debug=True)
