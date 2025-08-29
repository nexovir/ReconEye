from celery import shared_task, chain

@shared_task(bind=True, max_retries=None)
def orchestrator(self):
    try:
        check_programs.apply_async().get()
        check_assets.apply_async().get()
        url_monitor.apply_async().get()

        sendmessage("[WatchTower] ✅ One cycle finished. Taking a 15-minute break 💤", colour="GREEN")
        self.retry(countdown=15 * 60)

    except Exception as e:
        sendmessage(f"[WatchTower] ❌ Orchestrator failed: {e}", colour="RED")
        self.retry(countdown=15 * 60, exc=e)
