from django.contrib import admin
from django.utils.html import format_html
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, BlockedIP, SuspiciousIP


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'path', 'country', 'city', 'timestamp')
    list_filter = ('timestamp', 'country', 'city')
    search_fields = ('ip_address', 'path', 'country', 'city')
    date_hierarchy = 'timestamp'
    readonly_fields = ('ip_address', 'timestamp', 'path', 'country', 'city')
    
    def has_add_permission(self, request):
        # Logs are created automatically, not manually
        return False
    
    def has_change_permission(self, request, obj=None):
        # Logs should not be modified
        return False
    
    # Enable bulk delete for cleanup
    actions = ['delete_selected']


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = (
        'ip_address',
        'status_badge',
        'reason_short',
        'blocked_at',
        'request_count_24h'
    )
    list_filter = ('is_active', 'blocked_at')
    search_fields = ('ip_address', 'reason')
    date_hierarchy = 'blocked_at'
    readonly_fields = ('blocked_at',)
    
    fieldsets = (
        ('IP Information', {
            'fields': ('ip_address', 'is_active')
        }),
        ('Blocking Details', {
            'fields': ('reason', 'blocked_at')
        }),
    )
    
    def status_badge(self, obj):
        if obj.is_active:
            return format_html(
                '<span style="color: red; font-weight: bold;">● BLOCKED</span>'
            )
        return format_html(
            '<span style="color: gray;">○ Inactive</span>'
        )
    status_badge.short_description = 'Status'
    
    def reason_short(self, obj):
        if len(obj.reason) > 50:
            return obj.reason[:50] + '...'
        return obj.reason
    reason_short.short_description = 'Reason'
    
    def request_count_24h(self, obj):
        """Show recent request count for this IP"""
        from datetime import timedelta
        from django.utils import timezone
        
        yesterday = timezone.now() - timedelta(hours=24)
        count = RequestLog.objects.filter(
            ip_address=obj.ip_address,
            timestamp__gte=yesterday
        ).count()
        
        if count > 100:
            return format_html(
                '<span style="color: red; font-weight: bold;">{}</span>',
                count
            )
        return count
    
    request_count_24h.short_description = 'Requests (24h)'
    
    actions = ['activate_blocking', 'deactivate_blocking']
    
    def activate_blocking(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} IP(s) activated for blocking.')
    activate_blocking.short_description = 'Activate blocking for selected IPs'
    
    def deactivate_blocking(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} IP(s) deactivated.')
    deactivate_blocking.short_description = 'Deactivate blocking for selected IPs'


@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = (
        'ip_address',
        'reason_short',
        'request_count',
        'status_badge',
        'detected_at',
        'total_flags'
    )
    list_filter = ('is_resolved', 'detected_at')
    search_fields = ('ip_address', 'reason')
    date_hierarchy = 'detected_at'
    readonly_fields = ('detected_at', 'request_count')
    
    fieldsets = (
        ('IP Information', {
            'fields': ('ip_address', 'request_count')
        }),
        ('Suspicious Activity', {
            'fields': ('reason', 'detected_at', 'is_resolved')
        }),
    )
    
    def status_badge(self, obj):
        if obj.is_resolved:
            return format_html(
                '<span style="color: green;">✓ Resolved</span>'
            )
        return format_html(
            '<span style="color: orange; font-weight: bold;">⚠ Active</span>'
        )
    status_badge.short_description = 'Status'
    
    def reason_short(self, obj):
        if len(obj.reason) > 60:
            return obj.reason[:60] + '...'
        return obj.reason
    reason_short.short_description = 'Reason'
    
    def total_flags(self, obj):
        """Show total number of flags for this IP in last 24h"""
        yesterday = timezone.now() - timedelta(hours=24)
        count = SuspiciousIP.objects.filter(
            ip_address=obj.ip_address,
            detected_at__gte=yesterday
        ).count()
        
        if count >= 3:
            return format_html(
                '<span style="color: red; font-weight: bold;">{}</span>',
                count
            )
        return count
    
    total_flags.short_description = 'Flags (24h)'
    
    actions = ['mark_resolved', 'mark_unresolved', 'block_ips']
    
    def mark_resolved(self, request, queryset):
        updated = queryset.update(is_resolved=True)
        self.message_user(request, f'{updated} suspicious IP(s) marked as resolved.')
    mark_resolved.short_description = 'Mark as resolved'
    
    def mark_unresolved(self, request, queryset):
        updated = queryset.update(is_resolved=False)
        self.message_user(request, f'{updated} suspicious IP(s) marked as unresolved.')
    mark_unresolved.short_description = 'Mark as unresolved'
    
    def block_ips(self, request, queryset):
        """Block all selected suspicious IPs"""
        count = 0
        for suspicious_ip in queryset:
            BlockedIP.objects.get_or_create(
                ip_address=suspicious_ip.ip_address,
                defaults={
                    'reason': f'Blocked from admin due to: {suspicious_ip.reason}',
                    'is_active': True
                }
            )
            count += 1
        
        self.message_user(request, f'{count} IP(s) added to blocklist.')
    block_ips.short_description = 'Block selected IPs'


# Custom admin site header
admin.site.site_header = 'IP Tracking Administration'
admin.site.site_title = 'IP Tracking Admin'
admin.site.index_title = 'IP Tracking Management'