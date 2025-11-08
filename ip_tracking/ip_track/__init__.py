"""
Main project initialization.
Loads Celery app when Django starts.
"""
from .celery import app as celery_app

__all__ = ('celery_app',)


# ip_tracking/__init__.py
"""
IP Tracking Django application.
Provides middleware, models, and tasks for IP tracking and security.
"""
default_app_config = 'ip_tracking.apps.IpTrackingConfig'


# ip_tracking/management/__init__.py
"""Management commands package"""


# ip_tracking/management/commands/__init__.py
"""Custom management commands"""