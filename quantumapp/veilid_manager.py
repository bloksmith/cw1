import subprocess
import json
import os
from django.conf import settings

def start_veilid_node():
    try:
        subprocess.Popen([settings.VEILID_BINARY_PATH, '--config', settings.VEILID_CONFIG_PATH])
        print("Veilid node started successfully.")
    except Exception as e:
        print(f"Failed to start Veilid node: {e}")

def check_node_status():
    try:
        result = subprocess.run(['pgrep', '-f', settings.VEILID_BINARY_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return {'status': 'running'}
        else:
            return {'status': 'stopped'}
    except Exception as e:
        return {'status': 'error', 'details': str(e)}

def send_data_to_node(data):
    try:
        # Write the data to a temporary file
        command_file = '/tmp/veilid_command.json'
        with open(command_file, 'w') as f:
            json.dump(data, f)
        
        # Assuming veilid-cli can read commands from a file using the -f option
        result = subprocess.run(['veilid-cli', '-f', command_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Remove the temporary file
        os.remove(command_file)
        
        if result.returncode == 0:
            return {'status': 'Data sent'}
        else:
            return {'status': 'error', 'details': result.stderr}
    except Exception as e:
        return {'status': 'error', 'details': str(e)}

def receive_data_from_node():
    # Placeholder function since 'receive' command is not available
    return {'status': 'error', 'details': 'Receive command is not supported by veilid-cli'}

def get_wallets_syncing():
    try:
        result = subprocess.run(['veilid-cli', 'get-wallets'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            return {'status': 'error', 'details': result.stderr}
    except Exception as e:
        return {'status': 'error', 'details': str(e)}

def get_transactions_syncing():
    try:
        result = subprocess.run(['veilid-cli', 'get-transactions'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            return {'status': 'error', 'details': result.stderr}
    except Exception as e:
        return {'status': 'error', 'details': str(e)}

def get_peers():
    try:
        result = subprocess.run(['veilid-cli', 'get-peers'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            return {'status': 'error', 'details': result.stderr}
    except Exception as e:
        return {'status': 'error', 'details': str(e)}
