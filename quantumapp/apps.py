# apps.py (QuantumappConfig)
from django.apps import AppConfig
import threading
import logging
import subprocess
import os
import time

logger = logging.getLogger(__name__)

class QuantumappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'quantumapp'

    def ready(self):
        from django.db.models.signals import post_migrate
        from django.dispatch import receiver

        @receiver(post_migrate)
        def startup_tasks(sender, **kwargs):
            logger.info("Starting register with master node script")
            threading.Thread(target=run_script_with_retries, args=('register_with_master.py',)).start()
            logger.info("Starting WebSocket server")
            threading.Thread(target=start_websocket_server, daemon=True).start()

def run_script_with_retries(script_name, max_retries=5, retry_delay=5):
    import subprocess
    import os
    import time

    script_path = os.path.join(os.path.dirname(__file__), script_name)
    retries = 0

    while retries < max_retries:
        process = subprocess.Popen(['python3.9', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            logger.info("Script completed successfully")
            return
        else:
            logger.error(f"Script failed with return code {process.returncode}. Error: {stderr.decode()}")
        
        retries += 1
        logger.info(f"Retrying in {retry_delay} seconds... (Attempt {retries}/{max_retries})")
        time.sleep(retry_delay)

    logger.error("Max retry attempts reached. Could not complete the script execution.")
    cleanup_and_exit()

def cleanup_and_exit():
    # Implement any cleanup logic here if necessary
    logger.info("Cleaning up resources and exiting...")
    # Exit the application
    exit(1)

def start_websocket_server():
    import asyncio
    import websockets

    async def quantum_net_master(websocket, path):
        import json
        registered_nodes = []
        async for message in websocket:
            data = json.loads(message)
            
            if data["action"] == "register":
                multiaddress = data["multiaddress"]
                registered_nodes.append(multiaddress)
                await websocket.send(json.dumps({"status": "registered"}))
            
            elif data["action"] == "get_peers":
                await websocket.send(json.dumps({"peers": registered_nodes}))

    async def main():
        async with websockets.serve(quantum_net_master, "localhost", 8765):
            await asyncio.Future()  # run forever

    asyncio.run(main())
