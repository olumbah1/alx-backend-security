import logging
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin
from ipware import get_client_ip
from .models import RequestLog, BlockedIP

try:
    from django_ipgeolocation import GeoLocationService
    GEOLOCATION_AVAILABLE = True
except ImportError:
    GEOLOCATION_AVAILABLE = False

logger = logging.getLogger(__name__)


class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP addresses and block blacklisted IPs.
    Also performs geolocation lookup with caching.
    """
    
    def process_request(self, request):
        """Process incoming request before view execution"""
        # Get client IP address reliably (handles proxies)
        client_ip, is_routable = get_client_ip(request)
        
        if not client_ip:
            logger.warning("Could not determine client IP address")
            return None
        
        # Store IP in request for later use
        request.client_ip = client_ip
        
        # Check if IP is blacklisted (with caching for performance)
        cache_key = f"blocked_ip_{client_ip}"
        is_blocked = cache.get(cache_key)
        
        if is_blocked is None:
            # Check database
            is_blocked = BlockedIP.objects.filter(
                ip_address=client_ip,
                is_active=True
            ).exists()
            # Cache for 5 minutes
            cache.set(cache_key, is_blocked, 300)
        
        if is_blocked:
            logger.warning(f"Blocked request from blacklisted IP: {client_ip}")
            return HttpResponseForbidden(
                "Access denied. Your IP address has been blocked."
            )
        
        return None
    
    def process_response(self, request, response):
        """Log request after processing"""
        client_ip = getattr(request, 'client_ip', None)
        
        if not client_ip:
            return response
        
        # Get path
        path = request.path
        
        # Get geolocation data (with caching)
        country = None
        city = None
        
        if GEOLOCATION_AVAILABLE:
            geo_cache_key = f"geo_{client_ip}"
            geo_data = cache.get(geo_cache_key)
            
            if geo_data is None:
                try:
                    # Fetch geolocation data
                    geo_service = GeoLocationService()
                    location = geo_service.get_geolocation_for_ip(client_ip)
                    
                    if location:
                        country = location.get('country_name', '')
                        city = location.get('city', '')
                        geo_data = {'country': country, 'city': city}
                        # Cache for 24 hours
                        cache.set(geo_cache_key, geo_data, 86400)
                    else:
                        geo_data = {'country': '', 'city': ''}
                        # Cache negative results for shorter period
                        cache.set(geo_cache_key, geo_data, 3600)
                except Exception as e:
                    logger.error(f"Geolocation lookup failed for {client_ip}: {e}")
                    geo_data = {'country': '', 'city': ''}
            
            country = geo_data.get('country', '')
            city = geo_data.get('city', '')
        
        # Log request asynchronously to avoid blocking response
        try:
            RequestLog.objects.create(
                ip_address=client_ip,
                path=path,
                country=country or '',
                city=city or ''
            )
        except Exception as e:
            logger.error(f"Failed to log request: {e}")
        
        return response


class IPBlacklistMiddleware(MiddlewareMixin):
    """
    Simplified middleware focused only on IP blocking.
    Use this if you don't need logging in middleware.
    """
    
    def process_request(self, request):
        client_ip, is_routable = get_client_ip(request)
        
        if not client_ip:
            return None
        
        # Check blacklist with caching
        cache_key = f"blocked_ip_{client_ip}"
        is_blocked = cache.get(cache_key)
        
        if is_blocked is None:
            is_blocked = BlockedIP.objects.filter(
                ip_address=client_ip,
                is_active=True
            ).exists()
            cache.set(cache_key, is_blocked, 300)
        
        if is_blocked:
            return HttpResponseForbidden(
                "Access denied. Your IP address has been blocked."
            )
        
        return None