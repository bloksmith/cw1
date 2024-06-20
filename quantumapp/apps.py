from django.apps import AppConfig
import threading
import logging
import subprocess
import os

logger = logging.getLogger(__name__)

def run_script(script_name):
    script_path = os.path.join(os.path.dirname(__file__), script_name)
    subprocess.Popen(['python3.9', script_path])

class QuantumappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'quantumapp'

    def ready(self):
        logger.info("Starting register with master node script")
        threading.Thread(target=run_script, args=('register_with_master.py',)).start()
