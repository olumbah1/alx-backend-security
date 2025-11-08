from celery import shared_task
from django.utils import timezone
from django.db.models import Count
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)


@shared_task
def detect_anomalies():
    """
    Celery task to detect suspicious IP behavior.
    Runs hourly to identify:
    - IPs with excessive request rates (>100 requests/hour)
    - IPs accessing sensitive paths repeatedly
    """
    from .models import RequestLog, SuspiciousIP, BlockedIP
    
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    
    # Sensitive paths to monitor
    sensitive_paths = ['/admin', '/admin/', '/login', '/login/', '/api/admin']
    
    logger.info("Starting anomaly detection task")
    
    # 1. Detect IPs with high request volume
    high_volume_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=100)
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        # Check if already flagged recently
        recent_flag = SuspiciousIP.objects.filter(
            ip_address=ip_address,
            detected_at__gte=one_hour_ago,
            reason__contains='High request volume'
        ).exists()
        
        if not recent_flag:
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f'High request volume: {request_count} requests in the last hour',
                request_count=request_count
            )
            logger.warning(
                f"Flagged IP {ip_address} for high volume: {request_count} requests/hour"
            )
    
    # 2. Detect IPs accessing sensitive paths
    for path in sensitive_paths:
        suspicious_access = RequestLog.objects.filter(
            timestamp__gte=one_hour_ago,
            path__startswith=path
        ).values('ip_address').annotate(
            access_count=Count('id')
        ).filter(access_count__gt=10)
        
        for ip_data in suspicious_access:
            ip_address = ip_data['ip_address']
            access_count = ip_data['access_count']
            
            # Check if already flagged
            recent_flag = SuspiciousIP.objects.filter(
                ip_address=ip_address,
                detected_at__gte=one_hour_ago,
                reason__contains=f'Excessive access to {path}'
            ).exists()
            
            if not recent_flag:
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=f'Excessive access to {path}: {access_count} attempts in the last hour',
                    request_count=access_count
                )
                logger.warning(
                    f"Flagged IP {ip_address} for suspicious access to {path}: {access_count} attempts"
                )
    
    # 3. Auto-block IPs with multiple suspicious flags
    auto_block_threshold = 3
    repeat_offenders = SuspiciousIP.objects.filter(
        detected_at__gte=now - timedelta(days=1),
        is_resolved=False
    ).values('ip_address').annotate(
        flag_count=Count('id')
    ).filter(flag_count__gte=auto_block_threshold)
    
    for offender in repeat_offenders:
        ip_address = offender['ip_address']
        flag_count = offender['flag_count']
        
        # Check if already blocked
        if not BlockedIP.objects.filter(ip_address=ip_address, is_active=True).exists():
            BlockedIP.objects.create(
                ip_address=ip_address,
                reason=f'Auto-blocked: {flag_count} suspicious activity flags in 24 hours'
            )
            logger.critical(
                f"Auto-blocked IP {ip_address} after {flag_count} suspicious flags"
            )
    
    logger.info("Anomaly detection task completed")
    return {
        'high_volume_ips': high_volume_ips.count(),
        'auto_blocked': repeat_offenders.count()
    }


@shared_task
def cleanup_old_logs(days=30):
    """
    Clean up request logs older than specified days.
    Helps with GDPR/CCPA compliance and database performance.
    """
    from .models import RequestLog
    
    cutoff_date = timezone.now() - timedelta(days=days)
    deleted_count = RequestLog.objects.filter(
        timestamp__lt=cutoff_date
    ).delete()[0]
    
    logger.info(f"Deleted {deleted_count} request logs older than {days} days")
    return {'deleted_count': deleted_count}


@shared_task
def anonymize_old_ips(days=90):
    """
    Anonymize IP addresses in logs older than specified days.
    Replaces last octet with 0 for IPv4 (e.g., 192.168.1.100 -> 192.168.1.0)
    """
    from .models import RequestLog
    
    cutoff_date = timezone.now() - timedelta(days=days)
    logs_to_anonymize = RequestLog.objects.filter(
        timestamp__lt=cutoff_date
    ).exclude(ip_address__contains='0.0.0')
    
    count = 0
    for log in logs_to_anonymize.iterator(chunk_size=1000):
        # Simple anonymization: replace last octet with 0
        ip_parts = log.ip_address.split('.')
        if len(ip_parts) == 4:  # IPv4
            ip_parts[-1] = '0'
            log.ip_address = '.'.join(ip_parts)
            log.save(update_fields=['ip_address'])
            count += 1
    
    logger.info(f"Anonymized {count} IP addresses older than {days} days")
    return {'anonymized_count': count}


@shared_task
def generate_security_report():
    """
    Generate a daily security report summarizing IP activity.
    """
    from .models import RequestLog, SuspiciousIP, BlockedIP
    from django.db.models import Count
    
    now = timezone.now()
    yesterday = now - timedelta(days=1)
    
    report = {
        'date': yesterday.date(),
        'total_requests': RequestLog.objects.filter(
            timestamp__gte=yesterday
        ).count(),
        'unique_ips': RequestLog.objects.filter(
            timestamp__gte=yesterday
        ).values('ip_address').distinct().count(),
        'suspicious_ips': SuspiciousIP.objects.filter(
            detected_at__gte=yesterday
        ).count(),
        'blocked_ips': BlockedIP.objects.filter(
            blocked_at__gte=yesterday,
            is_active=True
        ).count(),
        'top_countries': list(RequestLog.objects.filter(
            timestamp__gte=yesterday,
            country__isnull=False
        ).exclude(country='').values('country').annotate(
            count=Count('id')
        ).order_by('-count')[:5])
    }
    
    logger.info(f"Security report generated: {report}")
    
    # You can extend this to send email notifications
    # from django.core.mail import send_mail
    # send_mail(
    #     'Daily Security Report',
    #     str(report),
    #     'security@example.com',
    #     ['admin@example.com'],
    # )
    
    return report