# IP Tracking System for Django

A comprehensive IP tracking, monitoring, and security system for Django applications with features including request logging, IP blacklisting, geolocation, rate limiting, and anomaly detection.

## Features

- ✅ **Request Logging**: Automatic logging of all incoming requests with IP addresses
- ✅ **IP Blacklisting**: Block malicious IPs with automatic or manual management
- ✅ **Geolocation**: Track geographic location of requests (country, city)
- ✅ **Rate Limiting**: Protect endpoints from abuse with configurable rate limits
- ✅ **Anomaly Detection**: Automated detection of suspicious behavior patterns
- ✅ **Privacy Compliance**: Built-in GDPR/CCPA compliance features
- ✅ **Performance Optimized**: Redis caching for high-traffic applications
- ✅ **Admin Dashboard**: Django admin integration for easy management

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Add to Django Settings

Add `ip_tracking` to your `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ... other apps
    'django_ratelimit',
    'django_ipgeolocation',
    'ip_tracking',
]
```

Add middleware to `MIDDLEWARE`:

```python
MIDDLEWARE = [
    # ... other middleware
    'ip_tracking.middleware.IPTrackingMiddleware',  # Add after authentication
]
```

### 3. Configure Settings

Copy the configuration from `settings.py` artifact to your Django settings file.

Key configurations:
- **Cache**: Configure Redis for production
- **Rate Limiting**: Set appropriate limits
- **Geolocation**: Add your API key
- **Celery**: Configure for async tasks

### 4. Run Migrations

```bash
python manage.py makemigrations ip_tracking
python manage.py migrate
```

### 5. Setup Redis (Production)

```bash
# Install Redis
sudo apt-get install redis-server

# Start Redis
redis-server
```

### 6. Setup Celery Worker

```bash
# Start Celery worker
celery -A your_project worker -l info

# Start Celery beat (for scheduled tasks)
celery -A your_project beat -l info
```

## Usage

### Task 0: Basic IP Logging

The middleware automatically logs every request:

```python
# Logs are created automatically
# View in Django admin or query programmatically
from ip_tracking.models import RequestLog

recent_logs = RequestLog.objects.all()[:100]
```

### Task 1: IP Blacklisting

Block IPs using the management command:

```bash
# Block an IP
python manage.py block_ip add --ip 192.168.1.100 --reason "Spam bot"

# Unblock an IP
python manage.py block_ip remove --ip 192.168.1.100

# List blocked IPs
python manage.py block_ip list

# List all (including inactive)
python manage.py block_ip list --all
```

Or programmatically:

```python
from ip_tracking.models import BlockedIP

# Block an IP
BlockedIP.objects.create(
    ip_address="192.168.1.100",
    reason="Detected malicious activity"
)
```

### Task 2: IP Geolocation

Geolocation is automatic when configured:

```python
# Get logs with location data
from ip_tracking.models import RequestLog

logs_from_country = RequestLog.objects.filter(country="United States")
logs_from_city = RequestLog.objects.filter(city="New York")
```

### Task 3: Rate Limiting

Apply rate limiting to views:

```python
from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def my_view(request):
    return render(request, 'template.html')

# Different rates for authenticated users
@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)
def api_endpoint(request):
    # Authenticated users: 10/min
    # Anonymous users: uses IP-based limiting
    pass
```

### Task 4: Anomaly Detection

Anomaly detection runs automatically via Celery. Manual trigger:

```python
from ip_tracking.tasks import detect_anomalies

# Run manually
result = detect_anomalies.delay()

# Check suspicious IPs
from ip_tracking.models import SuspiciousIP

suspicious = SuspiciousIP.objects.filter(is_resolved=False)
```

## Management Commands

### block_ip

Manage IP blacklist:

```bash
# Add IP to blacklist
python manage.py block_ip add --ip 10.0.0.1 --reason "Attack detected"

# Remove from blacklist
python manage.py block_ip remove --ip 10.0.0.1

# List blocked IPs
python manage.py block_ip list
```

## Celery Tasks

### detect_anomalies

Runs hourly to detect suspicious behavior:
- High request volume (>100 requests/hour)
- Repeated access to sensitive paths
- Auto-blocks repeat offenders

### cleanup_old_logs

Runs daily to delete old logs:

```python
from ip_tracking.tasks import cleanup_old_logs

# Delete logs older than 30 days
cleanup_old_logs.delay(days=30)
```

### anonymize_old_ips

Runs daily to anonymize old IP addresses:

```python
from ip_tracking.tasks import anonymize_old_ips

# Anonymize IPs older than 90 days
anonymize_old_ips.delay(days=90)
```

### generate_security_report

Generates daily security reports:

```python
from ip_tracking.tasks import generate_security_report

report = generate_security_report.delay()
```

## Admin Interface

Access the admin interface at `/admin/`:

- **Request Logs**: View all logged requests
- **Blocked IPs**: Manage blacklist
- **Suspicious IPs**: Review flagged IPs

Admin actions:
- Bulk block/unblock IPs
- Mark suspicious IPs as resolved
- View request statistics

## Configuration Options

### IP_TRACKING_SETTINGS

```python
IP_TRACKING_SETTINGS = {
    'ANONYMIZE_AFTER_DAYS': 90,
    'DELETE_AFTER_DAYS': 365,
    'ENABLE_GEOLOCATION': True,
    'AUTO_BLOCK_THRESHOLD': 3,
    'HIGH_VOLUME_THRESHOLD': 100,
}
```

### Rate Limiting

```python
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'
```

### Geolocation

```python
IPGEOLOCATION_SETTINGS = {
    'BACKEND': 'django_ipgeolocation.backends.IPGeolocationAPI',
    'API_KEY': 'your-api-key',
    'CACHE_TIMEOUT': 86400,  # 24 hours
}
```

## Privacy & Compliance

### GDPR/CCPA Compliance

The system includes several privacy features:

1. **Automatic Anonymization**: IPs older than 90 days are anonymized
2. **Automatic Deletion**: Logs older than 365 days are deleted
3. **Configurable Retention**: Adjust retention periods as needed
4. **User Transparency**: Update privacy policy to disclose tracking

### Best Practices

- Keep retention periods as short as practical
- Anonymize IPs before long-term storage
- Provide opt-out mechanisms where appropriate
- Document your data handling practices
- Regular audit of stored data

## Performance Optimization

### Database Indexes

The models include optimized indexes:

```python
class Meta:
    indexes = [
        models.Index(fields=['ip_address', 'timestamp']),
        models.Index(fields=['timestamp']),
    ]
```

### Caching Strategy

- Geolocation results: 24 hours
- Blocked IP checks: 5 minutes
- Rate limit counters: Per request basis

### Batch Processing

Use iterators for large datasets:

```python
for log in RequestLog.objects.iterator(chunk_size=1000):
    # Process log
    pass
```

## Monitoring & Alerts

### Logging

Logs are written to:
- Console (development)
- File: `logs/ip_tracking.log` (production)

### Metrics to Monitor

- Request volume per IP
- Blocked request attempts
- Suspicious IP flags
- Rate limit violations

### Setting Up Alerts

Extend `generate_security_report` to send email alerts:

```python
from django.core.mail import send_mail

def send_security_alert(report):
    send_mail(
        'Security Alert',
        f'Suspicious activity detected: {report}',
        'security@example.com',
        ['admin@example.com'],
    )
```

## Testing

Run tests:

```bash
pytest
```

Example test:

```python
from django.test import TestCase
from ip_tracking.models import RequestLog

class IPTrackingTestCase(TestCase):
    def test_logging(self):
        response = self.client.get('/')
        self.assertTrue(RequestLog.objects.exists())
```

## Troubleshooting

### Issue: IPs not being logged

- Check middleware is installed correctly
- Verify migrations are applied
- Check database connectivity

### Issue: Geolocation not working

- Verify API key is correct
- Check API quota/limits
- Ensure `django_ipgeolocation` is installed

### Issue: Rate limiting not working

- Verify Redis is running
- Check cache configuration
- Ensure middleware order is correct

### Issue: Celery tasks not running

- Start Celery worker and beat
- Check Redis connection
- Verify task registration

## Production Deployment

### Checklist

- [ ] Configure Redis for caching
- [ ] Set up Celery workers
- [ ] Configure logging to file
- [ ] Set appropriate rate limits
- [ ] Add geolocation API key
- [ ] Update privacy policy
- [ ] Configure database indexes
- [ ] Set up monitoring/alerts
- [ ] Test backup/restore procedures

### Environment Variables

```bash
DJANGO_SETTINGS_MODULE=ip_track.settings
CELERY_BROKER_URL=redis://localhost:6379/0
REDIS_URL=redis://localhost:6379/1
IPGEOLOCATION_API_KEY=your-api-key
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## License

This project is provided for educational purposes as part of ALX Backend Security curriculum.

## Support

For issues and questions:
- Review the documentation
- Check troubleshooting section
- Open an issue on GitHub

## Acknowledgments

- Django community
- Celery project
- Redis team
- IP geolocation service providers