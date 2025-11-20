"""
Email Automation and Integration System - Production Implementation
IMAP/OAuth integration, automated quarantine, takedown automation, incident response
"""
import asyncio
import imaplib
import email
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import uuid
import ssl
from dataclasses import dataclass
import aiohttp
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import poplib

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_
import aiofiles

from models.database import (
    EmailAnalysis, Organization, User, EmailIntegration, 
    QuarantineAction, TakedownRequest, IncidentResponse
)
from ai.detection_engine import ComprehensiveEmailAnalyzer
from realtime.processing import AutomatedResponseSystem
from core.config import settings

logger = logging.getLogger(__name__)

@dataclass
class EmailIntegrationConfig:
    """Email integration configuration"""
    integration_id: str
    organization_id: str
    provider: str  # gmail, outlook, exchange, imap
    auth_type: str  # oauth2, basic, app_password
    server_config: Dict[str, Any]
    credentials: Dict[str, str]
    sync_enabled: bool = True
    auto_quarantine: bool = True
    real_time_monitoring: bool = True

@dataclass
class QuarantineAction:
    """Quarantine action details"""
    action_id: str
    email_id: str
    action_type: str  # move, delete, flag, copy
    destination: str
    performed_at: datetime
    performed_by: str
    reason: str
    reversible: bool
    original_location: str

class EmailProviderIntegration:
    """Base class for email provider integrations"""
    
    def __init__(self, config: EmailIntegrationConfig):
        self.config = config
        self.analyzer = ComprehensiveEmailAnalyzer()
        
    async def connect(self) -> bool:
        """Establish connection to email provider"""
        raise NotImplementedError
        
    async def disconnect(self):
        """Disconnect from email provider"""
        raise NotImplementedError
        
    async def fetch_new_emails(self, since: datetime) -> List[Dict]:
        """Fetch new emails since timestamp"""
        raise NotImplementedError
        
    async def quarantine_email(self, email_id: str, reason: str) -> bool:
        """Move email to quarantine folder"""
        raise NotImplementedError
        
    async def restore_email(self, email_id: str, original_location: str) -> bool:
        """Restore quarantined email"""
        raise NotImplementedError
        
class IMAPIntegration(EmailProviderIntegration):
    """IMAP email integration for generic email servers"""
    
    def __init__(self, config: EmailIntegrationConfig):
        super().__init__(config)
        self.connection = None
        
    async def connect(self) -> bool:
        """Connect to IMAP server"""
        try:
            server_config = self.config.server_config
            host = server_config.get('host')
            port = server_config.get('port', 993)
            use_ssl = server_config.get('use_ssl', True)
            
            if use_ssl:
                self.connection = imaplib.IMAP4_SSL(host, port)
            else:
                self.connection = imaplib.IMAP4(host, port)
            
            # Authenticate
            credentials = self.config.credentials
            username = credentials.get('username')
            password = credentials.get('password')
            
            if self.config.auth_type == 'oauth2':
                # OAuth2 authentication
                auth_string = self._generate_oauth2_string(username, credentials.get('access_token'))
                self.connection.authenticate('XOAUTH2', lambda x: auth_string)
            else:
                # Basic authentication
                self.connection.login(username, password)
                
            logger.info(f"Connected to IMAP server: {host}")
            return True
            
        except Exception as e:
            logger.error(f"IMAP connection error: {e}")
            return False
            
    async def disconnect(self):
        """Disconnect from IMAP server"""
        try:
            if self.connection:
                self.connection.logout()
                self.connection = None
        except Exception as e:
            logger.error(f"IMAP disconnect error: {e}")
            
    async def fetch_new_emails(self, since: datetime) -> List[Dict]:
        """Fetch new emails from IMAP server"""
        emails = []
        
        try:
            if not self.connection:
                await self.connect()
                
            # Select inbox
            self.connection.select('INBOX')
            
            # Search for emails since timestamp
            since_str = since.strftime('%d-%b-%Y')
            typ, message_ids = self.connection.search(None, f'SINCE {since_str}')
            
            if typ != 'OK':
                logger.error("IMAP search failed")
                return emails
                
            message_id_list = message_ids[0].split()
            
            for message_id in message_id_list:
                try:
                    # Fetch email
                    typ, message_data = self.connection.fetch(message_id, '(RFC822)')
                    
                    if typ == 'OK':
                        raw_email = message_data[0][1]
                        parsed_email = await self._parse_email(raw_email, message_id.decode())
                        
                        if parsed_email:
                            emails.append(parsed_email)
                            
                except Exception as e:
                    logger.error(f"Error fetching email {message_id}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"IMAP fetch error: {e}")
            
        return emails
        
    async def quarantine_email(self, email_id: str, reason: str) -> bool:
        """Move email to quarantine folder"""
        try:
            if not self.connection:
                await self.connect()
                
            # Create quarantine folder if it doesn't exist
            try:
                self.connection.create('Quarantine')
            except:
                pass  # Folder might already exist
                
            # Move email to quarantine
            self.connection.select('INBOX')
            self.connection.move(email_id, 'Quarantine')
            self.connection.expunge()
            
            logger.info(f"Email {email_id} moved to quarantine: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Quarantine error: {e}")
            return False
            
    async def restore_email(self, email_id: str, original_location: str) -> bool:
        """Restore email from quarantine"""
        try:
            if not self.connection:
                await self.connect()
                
            # Move email back to original location
            self.connection.select('Quarantine')
            self.connection.move(email_id, original_location)
            self.connection.expunge()
            
            logger.info(f"Email {email_id} restored to {original_location}")
            return True
            
        except Exception as e:
            logger.error(f"Restore error: {e}")
            return False
            
    async def _parse_email(self, raw_email: bytes, message_id: str) -> Optional[Dict]:
        """Parse raw email into structured format"""
        try:
            msg = email.message_from_bytes(raw_email)
            
            # Extract headers
            headers = {
                'message_id': msg.get('Message-ID', message_id),
                'from': msg.get('From', ''),
                'to': msg.get('To', ''),
                'cc': msg.get('Cc', ''),
                'bcc': msg.get('Bcc', ''),
                'subject': msg.get('Subject', ''),
                'date': msg.get('Date', ''),
                'reply_to': msg.get('Reply-To', ''),
                'return_path': msg.get('Return-Path', ''),
                'received_spf': msg.get('Received-SPF', ''),
                'authentication_results': msg.get('Authentication-Results', ''),
            }
            
            # Extract content
            content = ""
            html_content = ""
            attachments = []
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition', ''))
                    
                    if content_type == 'text/plain' and 'attachment' not in content_disposition:
                        content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif content_type == 'text/html' and 'attachment' not in content_disposition:
                        html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif 'attachment' in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            attachments.append({
                                'filename': filename,
                                'content_type': content_type,
                                'size': len(part.get_payload(decode=True) or b''),
                                'content_id': part.get('Content-ID', '')
                            })
            else:
                content = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                
            # Parse date
            received_at = datetime.now()
            try:
                if headers['date']:
                    received_at = email.utils.parsedate_to_datetime(headers['date'])
            except:
                pass
                
            return {
                'external_id': message_id,
                'headers': headers,
                'sender_email': headers['from'],
                'recipient_email': headers['to'],
                'subject': headers['subject'],
                'content': content,
                'html_content': html_content,
                'attachments': attachments,
                'received_at': received_at,
                'raw_message': raw_email.decode('utf-8', errors='ignore')
            }
            
        except Exception as e:
            logger.error(f"Email parsing error: {e}")
            return None
            
    def _generate_oauth2_string(self, username: str, access_token: str) -> str:
        """Generate OAuth2 authentication string"""
        auth_string = f'user={username}\x01auth=Bearer {access_token}\x01\x01'
        return auth_string.encode('ascii')

class GmailIntegration(EmailProviderIntegration):
    """Gmail API integration using OAuth2"""
    
    def __init__(self, config: EmailIntegrationConfig):
        super().__init__(config)
        self.service = None
        
    async def connect(self) -> bool:
        """Connect to Gmail API"""
        try:
            from google.oauth2.credentials import Credentials
            from googleapiclient.discovery import build
            
            credentials_data = self.config.credentials
            creds = Credentials(
                token=credentials_data.get('access_token'),
                refresh_token=credentials_data.get('refresh_token'),
                token_uri=credentials_data.get('token_uri', 'https://oauth2.googleapis.com/token'),
                client_id=credentials_data.get('client_id'),
                client_secret=credentials_data.get('client_secret')
            )
            
            self.service = build('gmail', 'v1', credentials=creds)
            
            # Test connection
            profile = self.service.users().getProfile(userId='me').execute()
            logger.info(f"Connected to Gmail: {profile.get('emailAddress')}")
            return True
            
        except Exception as e:
            logger.error(f"Gmail connection error: {e}")
            return False
            
    async def fetch_new_emails(self, since: datetime) -> List[Dict]:
        """Fetch new emails from Gmail API"""
        emails = []
        
        try:
            if not self.service:
                await self.connect()
                
            # Convert timestamp to Gmail query format
            since_timestamp = int(since.timestamp())
            query = f'after:{since_timestamp}'
            
            # Get message list
            results = self.service.users().messages().list(
                userId='me',
                q=query,
                maxResults=100
            ).execute()
            
            messages = results.get('messages', [])
            
            for message in messages:
                try:
                    # Get full message
                    msg = self.service.users().messages().get(
                        userId='me',
                        id=message['id'],
                        format='full'
                    ).execute()
                    
                    parsed_email = await self._parse_gmail_message(msg)
                    if parsed_email:
                        emails.append(parsed_email)
                        
                except Exception as e:
                    logger.error(f"Error fetching Gmail message {message['id']}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Gmail fetch error: {e}")
            
        return emails
        
    async def quarantine_email(self, email_id: str, reason: str) -> bool:
        """Add quarantine label to Gmail email"""
        try:
            if not self.service:
                await self.connect()
                
            # Create quarantine label if it doesn't exist
            quarantine_label_id = await self._get_or_create_label('PHISHNET_QUARANTINE')
            
            # Add label to email
            self.service.users().messages().modify(
                userId='me',
                id=email_id,
                body={
                    'addLabelIds': [quarantine_label_id],
                    'removeLabelIds': ['INBOX']
                }
            ).execute()
            
            logger.info(f"Gmail email {email_id} quarantined: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Gmail quarantine error: {e}")
            return False
            
    async def _parse_gmail_message(self, msg: Dict) -> Optional[Dict]:
        """Parse Gmail API message format"""
        try:
            payload = msg['payload']
            headers = payload.get('headers', [])
            
            # Extract headers
            header_dict = {}
            for header in headers:
                header_dict[header['name'].lower()] = header['value']
                
            # Extract content
            content = ""
            html_content = ""
            attachments = []
            
            if 'parts' in payload:
                for part in payload['parts']:
                    await self._process_gmail_part(part, content, html_content, attachments)
            else:
                content = self._get_gmail_body(payload)
                
            return {
                'external_id': msg['id'],
                'headers': header_dict,
                'sender_email': header_dict.get('from', ''),
                'recipient_email': header_dict.get('to', ''),
                'subject': header_dict.get('subject', ''),
                'content': content,
                'html_content': html_content,
                'attachments': attachments,
                'received_at': datetime.fromtimestamp(int(msg['internalDate']) / 1000),
                'thread_id': msg.get('threadId')
            }
            
        except Exception as e:
            logger.error(f"Gmail message parsing error: {e}")
            return None
            
    async def _get_or_create_label(self, label_name: str) -> str:
        """Get or create Gmail label"""
        try:
            # List existing labels
            labels = self.service.users().labels().list(userId='me').execute()
            
            for label in labels.get('labels', []):
                if label['name'] == label_name:
                    return label['id']
                    
            # Create new label
            label_object = {
                'name': label_name,
                'messageListVisibility': 'show',
                'labelListVisibility': 'labelShow'
            }
            
            created_label = self.service.users().labels().create(
                userId='me',
                body=label_object
            ).execute()
            
            return created_label['id']
            
        except Exception as e:
            logger.error(f"Gmail label creation error: {e}")
            return None

class OutlookIntegration(EmailProviderIntegration):
    """Microsoft Graph API integration for Outlook/Exchange"""
    
    def __init__(self, config: EmailIntegrationConfig):
        super().__init__(config)
        self.access_token = None
        
    async def connect(self) -> bool:
        """Connect to Microsoft Graph API"""
        try:
            credentials = self.config.credentials
            self.access_token = credentials.get('access_token')
            
            # Test connection
            async with aiohttp.ClientSession() as session:
                headers = {'Authorization': f'Bearer {self.access_token}'}
                async with session.get(
                    'https://graph.microsoft.com/v1.0/me',
                    headers=headers
                ) as response:
                    if response.status == 200:
                        profile = await response.json()
                        logger.info(f"Connected to Outlook: {profile.get('mail')}")
                        return True
                    else:
                        logger.error(f"Outlook connection failed: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Outlook connection error: {e}")
            return False
            
    async def fetch_new_emails(self, since: datetime) -> List[Dict]:
        """Fetch new emails from Microsoft Graph API"""
        emails = []
        
        try:
            # Format timestamp for Graph API
            since_iso = since.strftime('%Y-%m-%dT%H:%M:%SZ')
            
            async with aiohttp.ClientSession() as session:
                headers = {'Authorization': f'Bearer {self.access_token}'}
                
                # Build query
                url = 'https://graph.microsoft.com/v1.0/me/messages'
                params = {
                    '$filter': f'receivedDateTime ge {since_iso}',
                    '$orderby': 'receivedDateTime desc',
                    '$top': 100
                }
                
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        messages = data.get('value', [])
                        
                        for message in messages:
                            parsed_email = await self._parse_outlook_message(message)
                            if parsed_email:
                                emails.append(parsed_email)
                    else:
                        logger.error(f"Outlook fetch failed: {response.status}")
                        
        except Exception as e:
            logger.error(f"Outlook fetch error: {e}")
            
        return emails
        
    async def quarantine_email(self, email_id: str, reason: str) -> bool:
        """Move Outlook email to quarantine folder"""
        try:
            # Create quarantine folder if needed
            quarantine_folder_id = await self._get_or_create_folder('PHISHNET_Quarantine')
            
            # Move email
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Authorization': f'Bearer {self.access_token}',
                    'Content-Type': 'application/json'
                }
                
                url = f'https://graph.microsoft.com/v1.0/me/messages/{email_id}/move'
                data = {'destinationId': quarantine_folder_id}
                
                async with session.post(url, headers=headers, json=data) as response:
                    if response.status == 201:
                        logger.info(f"Outlook email {email_id} quarantined: {reason}")
                        return True
                    else:
                        logger.error(f"Outlook quarantine failed: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Outlook quarantine error: {e}")
            return False

class EmailIntegrationManager:
    """Manage multiple email integrations and orchestrate operations"""
    
    def __init__(self):
        self.integrations: Dict[str, EmailProviderIntegration] = {}
        self.sync_tasks: Dict[str, asyncio.Task] = {}
        self.analyzer = ComprehensiveEmailAnalyzer()
        
    async def add_integration(self, config: EmailIntegrationConfig) -> bool:
        """Add new email integration"""
        try:
            # Create integration based on provider
            if config.provider == 'gmail':
                integration = GmailIntegration(config)
            elif config.provider == 'outlook':
                integration = OutlookIntegration(config)
            elif config.provider in ['imap', 'exchange']:
                integration = IMAPIntegration(config)
            else:
                logger.error(f"Unsupported provider: {config.provider}")
                return False
                
            # Test connection
            if await integration.connect():
                self.integrations[config.integration_id] = integration
                
                # Start sync task if enabled
                if config.sync_enabled:
                    await self._start_sync_task(config.integration_id)
                    
                logger.info(f"Integration added: {config.integration_id}")
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Error adding integration: {e}")
            return False
            
    async def remove_integration(self, integration_id: str):
        """Remove email integration"""
        try:
            # Stop sync task
            await self._stop_sync_task(integration_id)
            
            # Disconnect integration
            if integration_id in self.integrations:
                await self.integrations[integration_id].disconnect()
                del self.integrations[integration_id]
                
            logger.info(f"Integration removed: {integration_id}")
            
        except Exception as e:
            logger.error(f"Error removing integration: {e}")
            
    async def _start_sync_task(self, integration_id: str):
        """Start email synchronization task"""
        if integration_id in self.sync_tasks:
            self.sync_tasks[integration_id].cancel()
            
        task = asyncio.create_task(self._sync_emails_task(integration_id))
        self.sync_tasks[integration_id] = task
        
    async def _stop_sync_task(self, integration_id: str):
        """Stop email synchronization task"""
        if integration_id in self.sync_tasks:
            self.sync_tasks[integration_id].cancel()
            del self.sync_tasks[integration_id]
            
    async def _sync_emails_task(self, integration_id: str):
        """Background task to sync emails"""
        integration = self.integrations.get(integration_id)
        if not integration:
            return
            
        last_sync = datetime.now() - timedelta(hours=1)  # Start with 1 hour ago
        
        while True:
            try:
                # Fetch new emails
                new_emails = await integration.fetch_new_emails(last_sync)
                
                # Process each email
                for email_data in new_emails:
                    await self._process_incoming_email(email_data, integration_id)
                    
                # Update last sync time
                if new_emails:
                    last_sync = max(email['received_at'] for email in new_emails)
                    
                # Wait before next sync
                await asyncio.sleep(300)  # 5 minutes
                
            except asyncio.CancelledError:
                logger.info(f"Sync task cancelled for {integration_id}")
                break
            except Exception as e:
                logger.error(f"Sync task error for {integration_id}: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retry
                
    async def _process_incoming_email(self, email_data: Dict, integration_id: str):
        """Process incoming email through AI analysis"""
        try:
            # Run AI analysis
            analysis_result = await self.analyzer.analyze_email_comprehensive(
                content=email_data['content'],
                headers=email_data.get('headers'),
                attachments=email_data.get('attachments')
            )
            
            # Store analysis in database (would need database session here)
            # This would be called from the main application with proper DB session
            
            # Check if auto-quarantine is needed
            integration = self.integrations[integration_id]
            if (integration.config.auto_quarantine and 
                analysis_result['threat_level'] in ['CRITICAL', 'HIGH']):
                
                await integration.quarantine_email(
                    email_data['external_id'],
                    f"Automatic quarantine: {analysis_result['verdict']}"
                )
                
                logger.info(f"Auto-quarantined email {email_data['external_id']}")
                
        except Exception as e:
            logger.error(f"Error processing email {email_data.get('external_id')}: {e}")

class TakedownAutomationSystem:
    """Automated takedown and URL blocking system"""
    
    def __init__(self):
        self.takedown_providers = {}
        self._register_providers()
        
    def _register_providers(self):
        """Register takedown service providers"""
        self.takedown_providers = {
            'cloudflare': self._cloudflare_takedown,
            'aws_route53': self._route53_takedown,
            'google_safebrowsing': self._safebrowsing_report,
            'phishtank': self._phishtank_report,
            'registrar': self._registrar_takedown
        }
        
    async def initiate_takedown(
        self,
        malicious_url: str,
        evidence: Dict[str, Any],
        organization_id: str
    ) -> str:
        """Initiate automated takedown process"""
        
        takedown_id = str(uuid.uuid4())
        
        try:
            # Analyze URL and determine best takedown strategy
            takedown_strategy = await self._analyze_takedown_strategy(malicious_url)
            
            # Execute takedown actions
            results = []
            for provider in takedown_strategy['providers']:
                try:
                    result = await self.takedown_providers[provider](
                        malicious_url, 
                        evidence,
                        takedown_id
                    )
                    results.append(result)
                except Exception as e:
                    logger.error(f"Takedown provider {provider} failed: {e}")
                    
            # Store takedown request
            # This would store in database in real implementation
            
            logger.info(f"Takedown initiated: {takedown_id} for {malicious_url}")
            return takedown_id
            
        except Exception as e:
            logger.error(f"Takedown initiation error: {e}")
            return None
            
    async def _analyze_takedown_strategy(self, url: str) -> Dict[str, Any]:
        """Analyze URL to determine optimal takedown strategy"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        strategy = {
            'providers': [],
            'priority': 'high',
            'estimated_time': '2-24 hours'
        }
        
        # Add providers based on URL characteristics
        if any(cdn in domain for cdn in ['cloudflare', 'amazonaws', 'github.io']):
            strategy['providers'].append('cloudflare')
            
        # Always report to threat intelligence feeds
        strategy['providers'].extend([
            'google_safebrowsing',
            'phishtank'
        ])
        
        # If high-value target, contact registrar
        if strategy['priority'] == 'high':
            strategy['providers'].append('registrar')
            
        return strategy
        
    async def _cloudflare_takedown(self, url: str, evidence: Dict, takedown_id: str) -> Dict:
        """Submit takedown request to Cloudflare"""
        # Implementation would use Cloudflare API
        return {
            'provider': 'cloudflare',
            'status': 'submitted',
            'reference': f'CF-{takedown_id}',
            'estimated_completion': '2-6 hours'
        }
        
    async def _safebrowsing_report(self, url: str, evidence: Dict, takedown_id: str) -> Dict:
        """Report to Google Safe Browsing"""
        # Implementation would use Safe Browsing API
        return {
            'provider': 'google_safebrowsing',
            'status': 'submitted',
            'reference': f'GSB-{takedown_id}',
            'estimated_completion': '1-4 hours'
        }

class IncidentResponseAutomation:
    """Automated incident response workflows"""
    
    def __init__(self, response_system: AutomatedResponseSystem):
        self.response_system = response_system
        self.workflows = {}
        self._register_workflows()
        
    def _register_workflows(self):
        """Register incident response workflows"""
        self.workflows = {
            'phishing_campaign': self._phishing_campaign_workflow,
            'malware_outbreak': self._malware_outbreak_workflow,
            'credential_harvesting': self._credential_harvesting_workflow,
            'data_exfiltration': self._data_exfiltration_workflow
        }
        
    async def trigger_workflow(
        self,
        incident_type: str,
        incident_data: Dict[str, Any],
        db_session: AsyncSession
    ):
        """Trigger automated incident response workflow"""
        
        workflow = self.workflows.get(incident_type)
        if workflow:
            try:
                await workflow(incident_data, db_session)
                logger.info(f"Incident response workflow triggered: {incident_type}")
            except Exception as e:
                logger.error(f"Workflow execution error: {e}")
        else:
            logger.warning(f"No workflow for incident type: {incident_type}")
            
    async def _phishing_campaign_workflow(self, incident_data: Dict, db_session: AsyncSession):
        """Automated response to phishing campaign"""
        
        # 1. Quarantine all campaign emails
        campaign_id = incident_data.get('campaign_id')
        if campaign_id:
            await self._quarantine_campaign_emails(campaign_id, db_session)
            
        # 2. Block malicious domains/URLs
        malicious_urls = incident_data.get('malicious_urls', [])
        for url in malicious_urls:
            await self._add_url_to_blocklist(url, db_session)
            
        # 3. Notify affected users
        affected_users = incident_data.get('affected_users', [])
        await self._notify_users_phishing_attempt(affected_users, incident_data)
        
        # 4. Generate threat intelligence
        await self._generate_threat_intelligence(incident_data, db_session)
        
    async def _malware_outbreak_workflow(self, incident_data: Dict, db_session: AsyncSession):
        """Automated response to malware outbreak"""
        
        # 1. Immediate quarantine
        await self._emergency_quarantine(incident_data, db_session)
        
        # 2. Block malicious domains and IPs
        await self._block_malicious_infrastructure(incident_data, db_session)
        
        # 3. Trigger endpoint scans
        await self._trigger_endpoint_scans(incident_data.get('affected_systems', []))
        
        # 4. Isolate affected systems
        await self._isolate_systems(incident_data.get('compromised_systems', []))

# Global integration manager
email_integration_manager = EmailIntegrationManager()
takedown_system = TakedownAutomationSystem()

async def initialize_email_automation():
    """Initialize email automation systems"""
    logger.info("Email automation system initialized")
    return email_integration_manager, takedown_system