# core/tasks.py

from celery import shared_task, chain
from programs_monitor.tasks import check_programs
from asset_monitor.tasks import check_assets
from url_monitor.tasks import url_monitor
from programs_monitor.tasks import sendmessage


@shared_task(bind=True)
def orchestrator(self):

    workflow = chain(
        # check_programs.si(),
        # check_assets.si(),
        url_monitor.si()
    )

    workflow.apply_async()

    sendmessage("[WatchTower] ✅ One-time cycle executed. (No auto-reschedule)", colour="GREEN")
