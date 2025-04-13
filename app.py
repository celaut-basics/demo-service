#!/usr/bin/env python3.11

import os, logging, requests, threading
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

# Create the Flask application
app = Flask(__name__)

# Load service configuration (e.g., initial resources, node URL, etc.)
controller = Controller(debug=lambda s: logging.info('Node Controller: %s', s))
node_url: str = controller.get_node_url()
mem_limit: int = controller.get_mem_limit_at_start()

# Global variables for resources and gas
resources = {
    "mem_limit": mem_limit
}
gas_amount = 0

# Global variables for service
tiny_service = None
service_ready = False  # Flag indicating if the service has been added
services = []

logging.info('Gateway main directory: %s', node_url)

# HTML Templates
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

                loadServices();  // Reload services to update results
            } catch (error) {
                console.error('Error using services:', error);
            }
        }

        // Check every 3 seconds if the service is ready, and reload the page if it is
        async function checkServiceReady() {
            try {
                const response = await fetch('/service_status');
                const data = await response.json();
                if (data.ready) {
                    window.location.reload();
                } else {
                    setTimeout(checkServiceReady, 3000);
                }
            } catch (error) {
                console.error('Error checking service status:', error);
                setTimeout(checkServiceReady, 3000);
            }
        }

        updateDisplay();
        loadServices();
        // Start service readiness check
        checkServiceReady();
    </script>
</body>
</html>
"""

SPLASH_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="3">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loading Service</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .splash { text-align: center; }
    </style>
</head>
<body>
    <div class="splash">
        <h1>Loading service...</h1>
        <p>Please wait while the service is being initialized.</p>
    </div>
</body>
</html>
"""

# Function to initialize the tiny service in background
def init_tiny_service():
    global tiny_service, service_ready
    try:
        logging.info("Starting to add the tiny service...")
        tiny_service = controller.add_service(service_hash=TINY_SERVICE)
        service_ready = True
        logging.info("Tiny service initialized successfully.")
    except Exception as e:
        logging.error("Error initializing the tiny service: %s", str(e))

# Start background thread to avoid blocking the first web response
service_thread = threading.Thread(target=init_tiny_service, daemon=True)
service_thread.start()

@app.route('/service_status', methods=['GET'])
def service_status():
    return jsonify({"ready": service_ready})

@app.route('/')
def home():
    if not service_ready:
        logging.info('Service not ready yet. Showing splash screen.')
        return render_template_string(SPLASH_TEMPLATE)
    else:
        logging.info('Service is ready. Showing main page.')
        return render_template_string(HTML_TEMPLATE)

@app.route('/modify_max_memory', methods=['POST'])
def modify_mem_limit():
    try:
        max_mem_limit = request.json.get('max_mem_limit')
        logging.info('Updating memory limit to %s', max_mem_limit)
        if max_mem_limit is None:
            logging.warning('Request missing "max_mem_limit".')
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
        logging.error('Error updating memory limit: %s', str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/services', methods=['GET'])
def get_services():
    return jsonify([{"ip_port": service[0], "result": service[1]} for service in services])

@app.route('/generate_service', methods=['POST'])
def generate_service():
    try:
        service_uri = tiny_service.get_instance().uri
        new_service = (service_uri, "--")
        services.append(new_service)
        logging.info('New service generated: %s', new_service)
        return jsonify({"status": "Service generated", "service": new_service})
    except Exception as e:
        logging.error('Error generating service: %s', str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/use_services', methods=['POST'])
def use_services():
    try:
        for idx, service in enumerate(services):
            ip_port = service[0]
            try:
                response = requests.get(f"http://{ip_port}")
                result = response.text
            except requests.exceptions.RequestException as e:
                logging.error('Error contacting service at %s: %s', ip_port, str(e))
                result = 'Error'
            services[idx] = (ip_port, result)
            logging.info('Service updated at %s: %s', ip_port, result)
        return jsonify({"status": "Services used successfully", "services": services})
    except Exception as e:
        logging.error('Error using services: %s', str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/current_gas', methods=['GET'])
def current_gas():
    gas_scientific = "{:.2e}".format(gas_amount)
    logging.info('Current gas amount: %s', gas_scientific)
    return jsonify({"gas_amount": gas_scientific})

@app.route('/memory_usage', methods=['GET'])
def memory_usage():
    memory_used_bytes = resources.get('mem_limit', 0)
    memory_used_mb = memory_used_bytes / (1024 * 1024) if memory_used_bytes else 0
    memory_used_formatted = "{:.2f}".format(memory_used_mb)
    logging.info('Current memory usage: %s MB', memory_used_formatted)
    return jsonify({"memory_used": memory_used_formatted})

if __name__ == '__main__':
    logging.info('Starting Flask application.')
    app.run(host='0.0.0.0', port=5000, debug=True)
