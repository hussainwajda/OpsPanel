"""
Management command to clean up expired connection history records
This command should be run periodically (e.g., via cron) to remove connections older than 7 days
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from api.models import ServerConnectionHistory
from api.views import cleanup_expired_connections
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Clean up connection history records older than 7 days'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        
        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No records will be deleted'))
        
        try:
            from datetime import timedelta
            seven_days_ago = timezone.now() - timedelta(days=7)
            
            expired_connections = ServerConnectionHistory.objects.filter(
                last_connected__lt=seven_days_ago
            )
            
            count = expired_connections.count()
            
            if count == 0:
                self.stdout.write(self.style.SUCCESS('No expired connection history records found'))
                return
            
            self.stdout.write(f'Found {count} expired connection history record(s)')
            
            if dry_run:
                for conn in expired_connections[:10]:  # Show first 10
                    self.stdout.write(
                        f'  - {conn.user.username}: {conn.server_username}@{conn.server_ip} '
                        f'(last connected: {conn.last_connected})'
                    )
                if count > 10:
                    self.stdout.write(f'  ... and {count - 10} more')
            else:
                deleted_count = cleanup_expired_connections()
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Successfully cleaned up {deleted_count} expired connection history record(s)'
                    )
                )
                logger.info(f"Management command cleaned up {deleted_count} expired connection history records")
        
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error cleaning up connection history: {str(e)}')
            )
            logger.error(f"Error in cleanup_connection_history command: {str(e)}")
            raise

