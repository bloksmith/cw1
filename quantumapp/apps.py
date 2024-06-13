from django.apps import AppConfig
import os
import sys

class QuantumappConfig(AppConfig):
    name = 'quantumapp'

    def ready(self):
        import quantumapp.signals  # Import the signals module
        if os.environ.get('RUN_MAIN', None) != 'true' and 'migrate' not in sys.argv:
            from .scheduler import start_scheduler
            start_scheduler()
