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
    

class BlockedIP(models.Model):
    """Blacklist of blocked IP addresses"""
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    reason = models.TextField(blank=True)
    blocked_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ['-blocked_at']
    
    def __str__(self):
        return f"{self.ip_address} ({'Active' if self.is_active else 'Inactive'})"
    

class SuspiciousIP(models.Model):
    """Log of suspicious IP activity detected by anomaly detection"""
    ip_address = models.GenericIPAddressField(db_index=True)
    reason = models.TextField()
    detected_at = models.DateTimeField(default=timezone.now)
    request_count = models.IntegerField(default=0)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['ip_address', 'detected_at']),
            models.Index(fields=['is_resolved', 'detected_at']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason[:50]}"