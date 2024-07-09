import logging
from apscheduler.schedulers.background import BackgroundScheduler
from django_apscheduler.jobstores import DjangoJobStore, register_events
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .sync_utils import check_node_synchronization, synchronize_nodes

logger = logging.getLogger(__name__)

def periodic_synchronization_check():
    sync_status = check_node_synchronization()
    channel_layer = get_channel_layer()

    if not sync_status['is_synchronized']:
        synchronize_nodes()
        async_to_sync(channel_layer.group_send)(
            "sync_status", {
                "type": "sync_status_update",
                "message": {"status": "Nodes synchronized", "sync_status": sync_status},
            }
        )
        logger.info("Nodes synchronized")
    else:
        async_to_sync(channel_layer.group_send)(
            "sync_status", {
                "type": "sync_status_update",
                "message": {"status": "Nodes are synchronized", "sync_status": sync_status},
            }
        )
        logger.info("Nodes are synchronized")

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_jobstore(DjangoJobStore(), "default")

    scheduler.add_job(
        periodic_synchronization_check,
        trigger="interval",
        seconds=60,  # Adjust this interval as needed
        id="sync_check",
        replace_existing=True,
    )

    register_events(scheduler)
    scheduler.start()
    logger.info("Scheduler started!")
