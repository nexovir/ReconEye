# core/tasks.py

from celery import shared_task, chain
from programs_monitor.tasks import check_programs
from asset_monitor.tasks import check_assets
from url_monitor.tasks import url_monitor
from programs_monitor.tasks import sendmessage

@shared_task
def schedule_next_cycle():
    orchestrator.apply_async(countdown=15*60)

@shared_task(bind=True)
def orchestrator(self):
    """
    WatchTower orchestrator:
    - Executes tasks in strict order: check_programs -> check_assets -> url_monitor
    - Each task is independent; output of one does NOT go to the next
    - After all tasks finish, schedules next cycle after 15 minutes
    """

    workflow = chain(
        check_programs.si(),
        check_assets.si(),
        url_monitor.si()
    )

    workflow.apply_async(link=schedule_next_cycle.s())

    sendmessage("[WatchTower] ⏳ Cycle started. Will schedule next cycle after completion.", colour="BLUE")
