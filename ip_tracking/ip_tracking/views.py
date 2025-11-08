from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from ipware import get_client_ip
import logging

logger = logging.getLogger(__name__)


def get_rate_limit_key(group, request):
    """
    Custom key function for rate limiting.
    Returns IP address for rate limiting.
    """
    client_ip, is_routable = get_client_ip(request)
    return client_ip or 'unknown'


@ratelimit(
    key='ip',
    rate='5/m',
    method='POST',
    block=True
)
def login_view(request):
    """
    Login view with rate limiting.
    Anonymous users: 5 requests/minute
    """
    if request.method == 'POST':
        # Your login logic here
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Placeholder authentication logic
        return JsonResponse({
            'status': 'success',
            'message': 'Login successful'
        })
    
    return render(request, 'ip_tracking/login.html')


@ratelimit(
    key='user_or_ip',
    rate='10/m',
    method='POST',
    block=True
)
def api_endpoint(request):
    """
    API endpoint with rate limiting.
    Authenticated users: 10 requests/minute
    Anonymous users: uses IP-based limiting
    """
    client_ip, is_routable = get_client_ip(request)
    
    return JsonResponse({
        'status': 'success',
        'message': 'API request processed',
        'ip': client_ip,
        'authenticated': request.user.is_authenticated
    })


@ratelimit(
    key='ip',
    rate='5/m',
    method=['GET', 'POST'],
    block=True
)
def sensitive_endpoint(request):
    """
    Sensitive endpoint with strict rate limiting.
    5 requests/minute for all users.
    """
    return JsonResponse({
        'status': 'success',
        'message': 'Access granted to sensitive resource'
    })


@login_required
@ratelimit(
    key='user',
    rate='10/m',
    method='POST',
    block=True
)
def authenticated_action(request):
    """
    Action requiring authentication with per-user rate limiting.
    10 requests/minute per authenticated user.
    """
    if request.method == 'POST':
        # Your action logic here
        return JsonResponse({
            'status': 'success',
            'message': 'Action completed',
            'user': request.user.username
        })
    
    return JsonResponse({'status': 'error', 'message': 'POST required'})


def rate_limit_handler(request, exception):
    """
    Custom handler for rate limit exceptions.
    """
    client_ip, is_routable = get_client_ip(request)
    logger.warning(f"Rate limit exceeded for IP: {client_ip}")
    
    return JsonResponse({
        'status': 'error',
        'message': 'Rate limit exceeded. Please try again later.',
        'error_code': 'RATE_LIMIT_EXCEEDED'
    }, status=429)


# Dashboard view for monitoring
@login_required
def ip_dashboard(request):
    """
    Dashboard for monitoring IP activity.
    Requires authentication and staff permissions.
    """
    from .models import RequestLog, BlockedIP, SuspiciousIP
    from django.db.models import Count
    from datetime import timedelta
    from django.utils import timezone
    
    if not request.user.is_staff:
        return JsonResponse({
            'status': 'error',
            'message': 'Staff access required'
        }, status=403)
    
    # Get statistics
    now = timezone.now()
    last_hour = now - timedelta(hours=1)
    last_24h = now - timedelta(hours=24)
    
    context = {
        'total_requests_hour': RequestLog.objects.filter(
            timestamp__gte=last_hour
        ).count(),
        'total_requests_24h': RequestLog.objects.filter(
            timestamp__gte=last_24h
        ).count(),
        'blocked_ips': BlockedIP.objects.filter(is_active=True).count(),
        'suspicious_ips': SuspiciousIP.objects.filter(
            is_resolved=False
        ).count(),
        'top_ips': RequestLog.objects.filter(
            timestamp__gte=last_24h
        ).values('ip_address').annotate(
            count=Count('id')
        ).order_by('-count')[:10],
        'top_countries': RequestLog.objects.filter(
            timestamp__gte=last_24h,
            country__isnull=False
        ).exclude(country='').values('country').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
    }
    
    return render(request, 'ip_tracking/dashboard.html', context)