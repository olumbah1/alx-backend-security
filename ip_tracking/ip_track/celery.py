"""
Celery configuration for the Django project.
Place this file in your project root (same level as settings.py)
"""
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project.settings')

app = Celery('your_project')

# Load configuration from Django settings with CELERY_ prefix
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all registered Django apps
app.autodiscover_tasks()


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Debug task to test Celery setup"""
    print(f'Request: {self.request!r}')


# Configure periodic tasks
app.conf.beat_schedule = {
    'detect-anomalies-hourly': {
        'task': 'ip_tracking.tasks.detect_anomalies',
        'schedule': crontab(minute=0),  # Every hour at minute 0
    },
    'cleanup-old-logs-daily': {
        'task': 'ip_tracking.tasks.cleanup_old_logs',
        'schedule': crontab(hour=2, minute=0),  # Every day at 2:00 AM
        'kwargs': {'days': 30},
    },
    'anonymize-ips-daily': {
        'task': 'ip_tracking.tasks.anonymize_old_ips',
        'schedule': crontab(hour=3, minute=0),  # Every day at 3:00 AM
        'kwargs': {'days': 90},
    },
    'security-report-daily': {
        'task': 'ip_tracking.tasks.generate_security_report',
        'schedule': crontab(hour=8, minute=0),  # Every day at 8:00 AM
    },
}

# Celery configuration
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
)