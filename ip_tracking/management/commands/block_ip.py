from django.core.management.base import BaseCommand, CommandError
from django.core.cache import cache
from ip_tracking.models import BlockedIP
import ipaddress


class Command(BaseCommand):
    help = 'Block or unblock IP addresses'

    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            type=str,
            choices=['add', 'remove', 'list'],
            help='Action to perform: add, remove, or list blocked IPs'
        )
        parser.add_argument(
            '--ip',
            type=str,
            help='IP address to block or unblock'
        )
        parser.add_argument(
            '--reason',
            type=str,
            default='',
            help='Reason for blocking the IP'
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Show all blocked IPs including inactive ones'
        )

    def handle(self, *args, **options):
        action = options['action']
        ip_address = options.get('ip')
        reason = options.get('reason', '')
        show_all = options.get('all', False)

        if action == 'add':
            if not ip_address:
                raise CommandError('IP address is required for add action')
            
            # Validate IP address
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                raise CommandError(f'Invalid IP address: {ip_address}')
            
            # Add to blacklist
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={'reason': reason, 'is_active': True}
            )
            
            if not created:
                # Update existing entry
                blocked_ip.is_active = True
                blocked_ip.reason = reason
                blocked_ip.save()
                self.stdout.write(
                    self.style.WARNING(f'IP {ip_address} was already blocked. Updated.')
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully blocked IP: {ip_address}')
                )
            
            # Clear cache
            cache_key = f"blocked_ip_{ip_address}"
            cache.delete(cache_key)
            
        elif action == 'remove':
            if not ip_address:
                raise CommandError('IP address is required for remove action')
            
            try:
                blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
                blocked_ip.is_active = False
                blocked_ip.save()
                
                # Clear cache
                cache_key = f"blocked_ip_{ip_address}"
                cache.delete(cache_key)
                
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully unblocked IP: {ip_address}')
                )
            except BlockedIP.DoesNotExist:
                raise CommandError(f'IP {ip_address} is not in the blacklist')
        
        elif action == 'list':
            # List all blocked IPs
            if show_all:
                blocked_ips = BlockedIP.objects.all()
            else:
                blocked_ips = BlockedIP.objects.filter(is_active=True)
            
            if not blocked_ips.exists():
                self.stdout.write(
                    self.style.WARNING('No blocked IPs found')
                )
                return
            
            self.stdout.write(self.style.SUCCESS('Blocked IPs:'))
            self.stdout.write('-' * 80)
            
            for blocked_ip in blocked_ips:
                status = 'ACTIVE' if blocked_ip.is_active else 'INACTIVE'
                self.stdout.write(
                    f"{blocked_ip.ip_address:20} | "
                    f"{status:10} | "
                    f"{blocked_ip.blocked_at.strftime('%Y-%m-%d %H:%M:%S')} | "
                    f"{blocked_ip.reason[:40]}"
                )
            
            self.stdout.write('-' * 80)
            self.stdout.write(f'Total: {blocked_ips.count()} IP(s)')