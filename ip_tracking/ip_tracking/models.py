from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """Log of incoming requests with IP and geolocation data"""
    ip_address = models.GenericIPAddressField(db_index=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    path = models.CharField(max_length=500)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} at {self.timestamp}"