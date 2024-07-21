import threading
import subprocess
import os
import time
from django.apps import AppConfig
from django.db.models.signals import post_migrate
import logging

logger = logging.getLogger(__name__)
def startup_tasks(sender, **kwargs):
    logger.info("Entering startup_tasks...")
    try:
        logger.info("Starting register with master node script")
        thread_register = threading.Thread(target=run_script_with_retries, args=('register_with_master.py',))
        logger.info("Thread for register_with_master.py created")
        thread_register.start()
        logger.info("Thread for register_with_master.py started")
    except Exception as e:
        logger.error(f"Failed to start register_with_master.py thread: {e}", exc_info=True)

    try:
        logger.info("Starting WebSocket server")
        thread_ws = threading.Thread(target=start_websocket_server, daemon=True)
        logger.info("Thread for WebSocket server created")
        thread_ws.start()
        logger.info("Thread for WebSocket server started")
    except Exception as e:
        logger.error(f"Failed to start WebSocket server thread: {e}", exc_info=True)

class QuantumappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'quantumapp'

    def ready(self):
        logger.info("Entering QuantumappConfig.ready() method...")
        print("QuantumappConfig is ready")
        try:
            post_migrate.connect(lambda sender, **kwargs: startup_tasks(sender, **kwargs), sender=self.__class__)
            logger.info("post_migrate signal connected")
        except Exception as e:
            logger.error(f"Failed to connect post_migrate signal: {e}", exc_info=True)
        logger.info("Exiting QuantumappConfig.ready() method...")

def run_script_with_retries(script_name, max_retries=5, retry_delay=5):
    script_path = os.path.join(os.path.dirname(__file__), script_name)
    retries = 0

    while retries < max_retries:
        try:
            process = subprocess.Popen(['python3.9', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                logger.info("Script completed successfully")
                return
            else:
                logger.error(f"Script failed with return code {process.returncode}. Error: {stderr.decode()}")

        except Exception as e:
            logger.error(f"Exception occurred while running the script: {e}", exc_info=True)

        retries += 1
        logger.info(f"Retrying in {retry_delay} seconds... (Attempt {retries}/{max_retries})")
        time.sleep(retry_delay)

    logger.error("Max retry attempts reached. Could not complete the script execution.")
    cleanup_and_exit()

def cleanup_and_exit():
    logger.error("Cleaning up resources and exiting...")
    exit(1)

def start_websocket_server():
    import asyncio
    import websockets

    async def quantum_net_master(websocket, path):
        import json
        registered_nodes = []
        try:
            async for message in websocket:
                data = json.loads(message)

                if data["action"] == "register":
                    multiaddress = data["multiaddress"]
                    registered_nodes.append(multiaddress)
                    await websocket.send(json.dumps({"status": "registered"}))

                elif data["action"] == "get_peers":
                    await websocket.send(json.dumps({"peers": registered_nodes}))
        except Exception as e:
            logger.error(f"Exception occurred in WebSocket server: {e}", exc_info=True)

    async def main():
        try:
            async with websockets.serve(quantum_net_master, "localhost", 8765):
                await asyncio.Future()  # run forever
        except Exception as e:
            logger.error(f"Exception occurred while starting WebSocket server: {e}", exc_info=True)

    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"Exception occurred while running asyncio: {e}", exc_info=True)
class QuantumappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'quantumapp'

    def ready(self):
        logger.info("Entering QuantumappConfig.ready() method...")
        print("QuantumappConfig is ready")
        try:
            post_migrate.connect(self.startup_tasks, sender=self.__class__)
            logger.info("post_migrate signal connected")
        except Exception as e:
            logger.error(f"Failed to connect post_migrate signal: {e}", exc_info=True)
        logger.info("Exiting QuantumappConfig.ready() method...")

    def startup_tasks(self, sender, **kwargs):
        logger.info("Entering startup_tasks...")
        try:
            logger.info("Starting register with master node script")
            thread_register = threading.Thread(target=run_script_with_retries, args=('register_with_master.py',))
            logger.info("Thread for register_with_master.py created")
            thread_register.start()
            logger.info("Thread for register_with_master.py started")
        except Exception as e:
            logger.error(f"Failed to start register_with_master.py thread: {e}", exc_info=True)

        try:
            logger.info("Starting WebSocket server")
            thread_ws = threading.Thread(target=start_websocket_server, daemon=True)
            logger.info("Thread for WebSocket server created")
            thread_ws.start()
            logger.info("Thread for WebSocket server started")
        except Exception as e:
            logger.error(f"Failed to start WebSocket server thread: {e}", exc_info=True)
