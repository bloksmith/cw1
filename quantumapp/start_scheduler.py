import django
import logging
from quantumapp.scheduler import start_scheduler

# Initialize Django settings
django.setup()

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info("Starting the scheduler")
    start_scheduler()
