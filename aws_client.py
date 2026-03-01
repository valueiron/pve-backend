"""
AWS EC2 API Client Module
Handles connection to AWS EC2 API using boto3.
"""
import logging
import os
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class AWSClient:
    """Client for interacting with AWS EC2 API"""
    
    def __init__(self):
        """Initialize AWS API connection using environment variables"""
        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError as exc:
            raise ImportError("boto3 is not installed. Run: pip install boto3") from exc

        self._ClientError = ClientError  # used in _find_instance_region
        self.access_key_id     = os.getenv('AWS_ACCESS_KEY_ID', '').strip()
        self.secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY', '').strip()
        self.region            = os.getenv('AWS_REGION', '').strip()
        self.session_token     = os.getenv('AWS_SESSION_TOKEN', '').strip()

        if not all([self.access_key_id, self.secret_access_key]):
            raise ValueError(
                "Missing required AWS environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
            )
        
        # Create boto3 session
        session_kwargs = {
            'aws_access_key_id': self.access_key_id,
            'aws_secret_access_key': self.secret_access_key
        }
        
        if self.session_token:
            session_kwargs['aws_session_token'] = self.session_token
        
        if self.region:
            session_kwargs['region_name'] = self.region
        
        self.session = boto3.Session(**session_kwargs)
        
        # Create EC2 client
        if self.region:
            self.ec2_client = self.session.client('ec2', region_name=self.region)
        else:
            self.ec2_client = self.session.client('ec2', region_name='us-east-1')

        logger.info("[AWS Client] Initialized (region=%s)", self.region or 'all')
    
    def _normalize_status(self, state):
        """
        Normalize AWS EC2 instance state to match Proxmox status format.
        
        Args:
            state: AWS instance state name (e.g., 'running', 'stopped', 'pending')
            
        Returns:
            str: Normalized status ('running', 'stopped', etc.)
        """
        if not state:
            return 'unknown'
        
        state_lower = state.lower()
        
        status_map = {
            'running': 'running',
            'stopped': 'stopped',
            'stopping': 'stopped',
            'pending': 'running',  # Treat pending as running for UI
            'shutting-down': 'stopped',
            'terminated': 'stopped',
            'terminating': 'stopped',
        }
        
        return status_map.get(state_lower, 'unknown')
    
    def _extract_tags(self, resource):
        """
        Extract tags from an AWS resource and convert to array format.
        AWS tags are stored as an array of objects with 'Key' and 'Value' properties.
        We return both key and value, excluding the 'Name' tag as it's already displayed separately.
        
        Args:
            resource: AWS resource object/dictionary with Tags attribute
            
        Returns:
            list: List of dictionaries with 'key' and 'value' for key-value pairs
        """
        tags = []
        if isinstance(resource, dict):
            # Resource is a dictionary (common case)
            tags_list = resource.get('Tags', [])
        elif hasattr(resource, 'tags'):
            # Resource has a tags attribute
            tags_list = resource.tags if isinstance(resource.tags, list) else []
        else:
            return tags
        
        for tag in tags_list:
            if isinstance(tag, dict):
                tag_key = tag.get('Key', '')
                tag_value = tag.get('Value', '')
                # Exclude 'Name' tag as it's already displayed separately
                if tag_key and tag_key != 'Name':
                    tags.append({'key': tag_key, 'value': tag_value})
            elif hasattr(tag, 'key'):
                # Tag is an object with key and value attributes
                tag_key = tag.key if hasattr(tag, 'key') else ''
                tag_value = tag.value if hasattr(tag, 'value') else ''
                if tag_key and tag_key != 'Name':
                    tags.append({'key': tag_key, 'value': tag_value})
        
        return tags
    
    def _generate_instance_id(self, instance_id, region):
        """
        Generate a unique VM ID for AWS instances.
        
        Args:
            instance_id: AWS EC2 instance ID (e.g., 'i-1234567890abcdef0')
            region: AWS region name
            
        Returns:
            str: Unique VM ID
        """
        return f"aws-{region}-{instance_id}"
    
    def _parse_instance_id(self, vm_id):
        """
        Parse AWS VM ID back to region and instance ID.
        
        Args:
            vm_id: AWS VM ID (format: aws-{region}-{instance_id})
            
        Returns:
            tuple: (region, instance_id)
        """
        if not vm_id.startswith('aws-'):
            raise ValueError(f"Invalid AWS VM ID format: {vm_id}")
        
        parts = vm_id[4:].split('-', 1)  # Remove 'aws-' prefix
        if len(parts) != 2:
            raise ValueError(f"Invalid AWS VM ID format: {vm_id}")
        
        return parts[0], parts[1]
    
    def _get_instance_metrics(self, instance):
        """
        Extract metrics from AWS EC2 instance.
        
        Args:
            instance: AWS EC2 instance object
            
        Returns:
            dict: Metrics including CPU, memory, disk usage
        """
        metrics = {
            'cpu': 0.0,
            'mem': 0,
            'maxmem': 0,
            'disk': 0,
            'maxdisk': 0,
            'uptime': 0
        }
        
        try:
            # Get instance type info (memory and CPU info)
            instance_type = instance.get('InstanceType', '')
            
            # Calculate uptime from launch time
            if instance.get('LaunchTime'):
                launch_time = instance['LaunchTime']
                if isinstance(launch_time, str):
                    launch_time = datetime.fromisoformat(launch_time.replace('Z', '+00:00'))
                elif isinstance(launch_time, datetime):
                    if launch_time.tzinfo is None:
                        launch_time = launch_time.replace(tzinfo=timezone.utc)
                
                now = datetime.now(timezone.utc)
                uptime_seconds = int((now - launch_time).total_seconds())
                metrics['uptime'] = uptime_seconds
            
            # Get block device information for disk size
            block_devices = instance.get('BlockDeviceMappings', [])
            total_disk_gb = 0
            for device in block_devices:
                ebs = device.get('Ebs', {})
                if ebs:
                    # Get volume size from EBS volume
                    # Note: This requires additional API call to get actual volume size
                    # For now, we'll approximate or leave as 0
                    pass
            
            # Note: Real-time CPU and memory usage require CloudWatch metrics
            # which would need additional API calls. For now, we return defaults.
            
        except Exception as e:
            logger.warning("[AWS] Could not get metrics for instance %s: %s", instance.get('InstanceId', 'unknown'), e)
        
        return metrics
    
    def _get_all_regions(self):
        """
        Get list of all AWS regions.
        
        Returns:
            list: List of region names
        """
        try:
            ec2 = self.session.client('ec2', region_name='us-east-1')
            response = ec2.describe_regions()
            regions = [region['RegionName'] for region in response['Regions']]
            return regions
        except Exception as e:
            logger.warning("[AWS] Could not list regions: %s", e)
            # Return default regions if listing fails
            return [self.region] if self.region else ['us-east-1']
    
    def _fetch_region_vms(self, region):
        """Fetch all EC2 instances in a single region. Runs in a thread pool."""
        ec2_client = self.session.client('ec2', region_name=region)
        instances = []
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id       = instance.get('InstanceId', '')
                    state             = instance.get('State', {}).get('Name', 'unknown')
                    metrics           = self._get_instance_metrics(instance)
                    availability_zone = instance.get('Placement', {}).get('AvailabilityZone', region)
                    instance_type     = instance.get('InstanceType', 'unknown')

                    name = instance_id
                    for tag in instance.get('Tags', []):
                        if tag.get('Key') == 'Name':
                            name = tag.get('Value', instance_id)
                            break

                    vm_info = {
                        'vmid':              self._generate_instance_id(instance_id, region),
                        'name':              name,
                        'status':            self._normalize_status(state),
                        'node':              availability_zone,
                        'type':              'aws',
                        'cpu':               metrics['cpu'],
                        'mem':               metrics['mem'],
                        'maxmem':            metrics['maxmem'],
                        'disk':              metrics['disk'],
                        'maxdisk':           metrics['maxdisk'],
                        'uptime':            metrics['uptime'],
                        'region':            region,
                        'instance_id':       instance_id,
                        'instance_type':     instance_type,
                        'availability_zone': availability_zone,
                        'tags':              self._extract_tags(instance),
                    }
                    if instance.get('PublicIpAddress'):
                        vm_info['public_ip'] = instance['PublicIpAddress']
                    if instance.get('PrivateIpAddress'):
                        vm_info['private_ip'] = instance['PrivateIpAddress']
                    instances.append(vm_info)
        return instances

    def get_all_vms(self):
        """
        Fetch all EC2 instances from all regions (or configured region) in parallel.

        Returns:
            list: List of dictionaries containing VM information
        """
        logger.info("[AWS] Starting instance fetch")
        regions = [self.region] if self.region else self._get_all_regions()
        if not regions:
            logger.warning("[AWS] No regions found")
            return []

        all_instances = []
        with ThreadPoolExecutor(max_workers=min(len(regions), 10)) as executor:
            futures = {executor.submit(self._fetch_region_vms, r): r for r in regions}
            for future in as_completed(futures):
                region = futures[future]
                try:
                    instances = future.result()
                    all_instances.extend(instances)
                    logger.info("[AWS] Fetched %d instance(s) from %s", len(instances), region)
                except Exception as e:
                    logger.error("[AWS] Error fetching instances from %s: %s", region, e)

        logger.info("[AWS] Total AWS instances found: %d", len(all_instances))
        return all_instances
    
    def _find_instance_region(self, instance_id):
        """
        Find which region an instance belongs to by searching across regions.
        
        Args:
            instance_id: EC2 instance ID
            
        Returns:
            str: Region name where the instance is located
        """
        regions = self._get_all_regions() if not self.region else [self.region]
        
        for region in regions:
            try:
                ec2_client = self.session.client('ec2', region_name=region)
                response = ec2_client.describe_instances(InstanceIds=[instance_id])
                if response.get('Reservations'):
                    return region
            except self._ClientError:
                # Instance not in this region, continue
                continue
        
        raise ValueError(f"Instance {instance_id} not found in any region")
    
    def get_vm_details(self, vm_id):
        """
        Get detailed information about a specific EC2 instance.
        
        Args:
            vm_id: AWS VM ID (format: aws-{region}-{instance_id})
            
        Returns:
            dict: Detailed VM information
        """
        try:
            region, instance_id = self._parse_instance_id(vm_id)
            
            # Create EC2 client for this region
            ec2_client = self.session.client('ec2', region_name=region)
            
            # Get instance details
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            
            if not response.get('Reservations') or not response['Reservations'][0].get('Instances'):
                raise ValueError(f"Instance {instance_id} not found in region {region}")
            
            instance = response['Reservations'][0]['Instances'][0]
            
            # Get metrics
            metrics = self._get_instance_metrics(instance)
            
            # Get instance name from tags
            name = instance_id
            for tag in instance.get('Tags', []):
                if tag.get('Key') == 'Name':
                    name = tag.get('Value', instance_id)
                    break
            
            state = instance.get('State', {}).get('Name', 'unknown')
            instance_type = instance.get('InstanceType', 'unknown')
            availability_zone = instance.get('Placement', {}).get('AvailabilityZone', region)
            
            # Extract tags
            tags = self._extract_tags(instance)
            
            # Build detailed VM info
            vm_details = {
                'vmid': vm_id,
                'name': name,
                'status': self._normalize_status(state),
                'node': availability_zone,
                'type': 'aws',
                'cpu': metrics['cpu'],
                'mem': metrics['mem'],
                'maxmem': metrics['maxmem'],
                'disk': metrics['disk'],
                'maxdisk': metrics['maxdisk'],
                'uptime': metrics['uptime'],
                'region': region,
                'instance_id': instance_id,
                'instance_type': instance_type,
                'availability_zone': availability_zone,
                'tags': tags
            }
            
            # Add network info
            if instance.get('PublicIpAddress'):
                vm_details['public_ip'] = instance['PublicIpAddress']
            if instance.get('PrivateIpAddress'):
                vm_details['private_ip'] = instance['PrivateIpAddress']
            
            # Add security groups
            if instance.get('SecurityGroups'):
                vm_details['security_groups'] = [
                    sg.get('GroupName') for sg in instance['SecurityGroups']
                ]
            
            # Add VPC and subnet info
            if instance.get('VpcId'):
                vm_details['vpc_id'] = instance['VpcId']
            if instance.get('SubnetId'):
                vm_details['subnet_id'] = instance['SubnetId']
            
            return vm_details
        
        except ValueError:
            raise
        except Exception as e:
            raise Exception(f"Error fetching instance details: {str(e)}")
    
    def start_vm(self, vm_id):
        """
        Start an EC2 instance.
        
        Args:
            vm_id: AWS VM ID (format: aws-{region}-{instance_id})
            
        Returns:
            dict: Operation result
        """
        try:
            region, instance_id = self._parse_instance_id(vm_id)
            
            # Create EC2 client for this region
            ec2_client = self.session.client('ec2', region_name=region)
            
            # Start the instance
            ec2_client.start_instances(InstanceIds=[instance_id])
            
            # Wait for the instance to be running (optional, can be async)
            # For now, we'll just return success and let the status update on next refresh
            waiter = ec2_client.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 5, 'MaxAttempts': 40})
            
            return {
                'status': 'success',
                'message': f'Instance {instance_id} started successfully'
            }
        
        except ValueError:
            raise
        except Exception as e:
            raise Exception(f"Error starting instance {vm_id}: {str(e)}")
    
    def stop_vm(self, vm_id):
        """
        Stop an EC2 instance.
        
        Args:
            vm_id: AWS VM ID (format: aws-{region}-{instance_id})
            
        Returns:
            dict: Operation result
        """
        try:
            region, instance_id = self._parse_instance_id(vm_id)
            
            # Create EC2 client for this region
            ec2_client = self.session.client('ec2', region_name=region)
            
            # Stop the instance
            ec2_client.stop_instances(InstanceIds=[instance_id])
            
            # Wait for the instance to be stopped
            waiter = ec2_client.get_waiter('instance_stopped')
            waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 5, 'MaxAttempts': 40})
            
            return {
                'status': 'success',
                'message': f'Instance {instance_id} stopped successfully'
            }
        
        except ValueError:
            raise
        except Exception as e:
            raise Exception(f"Error stopping instance {vm_id}: {str(e)}")
    
    def _fetch_region_networking(self, region):
        """Fetch all networking resources in a single region. Runs in a thread pool."""
        ec2_client = self.session.client('ec2', region_name=region)
        vpcs, subnets, security_groups, elastic_ips = [], [], [], []

        for vpc in ec2_client.describe_vpcs().get('Vpcs', []):
            info = {
                'id':            vpc['VpcId'],
                'name':          None,
                'cidr_block':    vpc.get('CidrBlock', ''),
                'state':         vpc.get('State', ''),
                'region':        region,
                'type':          'aws',
                'resource_type': 'vpc',
                'tags':          self._extract_tags(vpc),
            }
            for tag in vpc.get('Tags', []):
                if tag.get('Key') == 'Name':
                    info['name'] = tag.get('Value')
                    break
            vpcs.append(info)

        for subnet in ec2_client.describe_subnets().get('Subnets', []):
            info = {
                'id':                subnet['SubnetId'],
                'name':              None,
                'vpc_id':            subnet.get('VpcId', ''),
                'cidr_block':        subnet.get('CidrBlock', ''),
                'availability_zone': subnet.get('AvailabilityZone', ''),
                'state':             subnet.get('State', ''),
                'region':            region,
                'type':              'aws',
                'resource_type':     'subnet',
                'tags':              self._extract_tags(subnet),
            }
            for tag in subnet.get('Tags', []):
                if tag.get('Key') == 'Name':
                    info['name'] = tag.get('Value')
                    break
            subnets.append(info)

        for sg in ec2_client.describe_security_groups().get('SecurityGroups', []):
            security_groups.append({
                'id':            sg['GroupId'],
                'name':          sg.get('GroupName', ''),
                'vpc_id':        sg.get('VpcId', ''),
                'description':   sg.get('Description', ''),
                'region':        region,
                'type':          'aws',
                'resource_type': 'security_group',
                'tags':          self._extract_tags(sg),
            })

        for eip in ec2_client.describe_addresses().get('Addresses', []):
            elastic_ips.append({
                'id':            eip.get('AllocationId', eip.get('PublicIp', '')),
                'name':          None,
                'public_ip':     eip.get('PublicIp', ''),
                'private_ip':    eip.get('PrivateIpAddress', ''),
                'instance_id':   eip.get('InstanceId', ''),
                'domain':        eip.get('Domain', 'vpc'),
                'region':        region,
                'type':          'aws',
                'resource_type': 'elastic_ip',
                'tags':          self._extract_tags(eip),
            })

        return vpcs, subnets, security_groups, elastic_ips

    def get_all_networking(self):
        """
        Fetch all networking resources (VPCs, Subnets, Security Groups, Elastic IPs) in parallel.

        Returns:
            dict: Dictionary containing lists of networking resources
        """
        logger.info("[AWS] Starting networking fetch")
        result = {'vpcs': [], 'subnets': [], 'security_groups': [], 'elastic_ips': []}
        regions = [self.region] if self.region else self._get_all_regions()

        with ThreadPoolExecutor(max_workers=min(len(regions), 10)) as executor:
            futures = {executor.submit(self._fetch_region_networking, r): r for r in regions}
            for future in as_completed(futures):
                region = futures[future]
                try:
                    vpcs, subnets, sgs, eips = future.result()
                    result['vpcs'].extend(vpcs)
                    result['subnets'].extend(subnets)
                    result['security_groups'].extend(sgs)
                    result['elastic_ips'].extend(eips)
                except Exception as e:
                    logger.error("[AWS] Error fetching networking from %s: %s", region, e)

        logger.info(
            "[AWS] Networking: %d VPCs, %d Subnets, %d SGs, %d EIPs",
            len(result['vpcs']), len(result['subnets']),
            len(result['security_groups']), len(result['elastic_ips']),
        )
        return result
    
    def get_all_storage(self):
        """
        Fetch all S3 buckets.

        Returns:
            dict: Dictionary containing list of S3 buckets
        """
        logger.info("[AWS] Starting S3 bucket fetch")
        result = {'buckets': []}
        s3_region = self.region if self.region else 'us-east-1'
        s3_client = self.session.client('s3', region_name=s3_region)

        try:
            response = s3_client.list_buckets()

            for bucket in response.get('Buckets', []):
                bucket_name   = bucket.get('Name', '')
                creation_date = bucket.get('CreationDate')

                try:
                    loc = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = loc.get('LocationConstraint') or 'us-east-1'
                except Exception:
                    bucket_region = s3_region

                tags = []
                try:
                    tagging = s3_client.get_bucket_tagging(Bucket=bucket_name)
                    tags = [
                        tag.get('Key', '') for tag in tagging.get('TagSet', [])
                        if tag.get('Key') and tag.get('Key') != 'Name'
                    ]
                except Exception:
                    pass

                result['buckets'].append({
                    'id':            bucket_name,
                    'name':          bucket_name,
                    'region':        bucket_region,
                    'creation_date': creation_date.isoformat() if creation_date else None,
                    'type':          'aws',
                    'resource_type': 's3_bucket',
                    'tags':          tags,
                })

            logger.info("[AWS] Found %d S3 bucket(s)", len(result['buckets']))
            return result

        except Exception as e:
            logger.error("[AWS] Error listing S3 buckets: %s", e)
            return result

# Global instance (lazy initialization)
_aws_client = None
_aws_client_lock = threading.Lock()

def get_aws_client():
    """Get or create the global AWS client instance."""
    global _aws_client
    if _aws_client is None:
        with _aws_client_lock:
            if _aws_client is None:  # re-check after acquiring lock
                try:
                    _aws_client = AWSClient()
                    logger.info("[AWS Client] Initialized successfully")
                except (ValueError, ImportError) as e:
                    logger.warning("[AWS Client] Not available: %s", e)
                    return None
                except Exception as e:
                    logger.error("[AWS Client] Initialization failed: %s", e)
                    return None
    return _aws_client
