"""
AWS EC2 API Client Module
Handles connection to AWS EC2 API using boto3.
"""
import os
import sys
import re
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

class AWSClient:
    """Client for interacting with AWS EC2 API"""
    
    def __init__(self):
        """Initialize AWS API connection using environment variables"""
        if not BOTO3_AVAILABLE:
            raise ImportError("boto3 is not installed. Please install it using: pip install boto3")
        
        sys.stderr.write("[AWS Client] Initializing AWSClient...\n")
        sys.stderr.flush()
        
        self.access_key_id = os.getenv('AWS_ACCESS_KEY_ID', '').strip()
        self.secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY', '').strip()
        self.region = os.getenv('AWS_REGION', '').strip()
        self.session_token = os.getenv('AWS_SESSION_TOKEN', '').strip()  # Optional, for temporary credentials
        
        sys.stderr.write(f"[AWS Client] Environment check - ACCESS_KEY_ID: {'SET' if self.access_key_id else 'NOT SET'}, SECRET_ACCESS_KEY: {'SET' if self.secret_access_key else 'NOT SET'}, REGION: {'SET' if self.region else 'NOT SET'}\n")
        sys.stderr.flush()
        
        if not all([self.access_key_id, self.secret_access_key]):
            error_msg = (
                "Missing required AWS environment variables. "
                "Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
            )
            sys.stderr.write(f"[AWS Client] ERROR: {error_msg}\n")
            sys.stderr.flush()
            raise ValueError(error_msg)
        
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
            # Default region if not specified
            self.ec2_client = self.session.client('ec2', region_name='us-east-1')
        
        sys.stderr.write("[AWS Client] AWS client initialized successfully\n")
        sys.stderr.flush()
    
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
            sys.stderr.write(f"[AWS Client] Warning: Could not get metrics for instance {instance.get('InstanceId', 'unknown')}: {str(e)}\n")
            sys.stderr.flush()
        
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
            sys.stderr.write(f"[AWS Client] Warning: Could not list regions: {str(e)}\n")
            sys.stderr.flush()
            # Return default regions if listing fails
            return [self.region] if self.region else ['us-east-1']
    
    def get_all_vms(self):
        """
        Fetch all EC2 instances from all regions (or configured region).
        
        Returns:
            list: List of dictionaries containing VM information
        """
        sys.stderr.write("[AWS get_all_vms] Starting instance fetch...\n")
        sys.stderr.flush()
        
        all_instances = []
        
        try:
            # Determine which regions to search
            if self.region:
                regions = [self.region]
                sys.stderr.write(f"[AWS get_all_vms] Using configured region: {self.region}\n")
                sys.stderr.flush()
            else:
                # Search all regions
                regions = self._get_all_regions()
                sys.stderr.write(f"[AWS get_all_vms] Searching {len(regions)} region(s)\n")
                sys.stderr.flush()
            
            if not regions:
                sys.stderr.write("[AWS get_all_vms] WARNING: No regions found!\n")
                sys.stderr.flush()
                return all_instances
            
            # Iterate through regions
            for region in regions:
                try:
                    sys.stderr.write(f"[AWS get_all_vms] Processing region: {region}\n")
                    sys.stderr.flush()
                    
                    # Create EC2 client for this region
                    ec2_client = self.session.client('ec2', region_name=region)
                    
                    # List all instances in this region
                    sys.stderr.write(f"[AWS get_all_vms] Listing instances in region {region}...\n")
                    sys.stderr.flush()
                    
                    paginator = ec2_client.get_paginator('describe_instances')
                    instance_count = 0
                    processed_count = 0
                    
                    for page in paginator.paginate():
                        for reservation in page.get('Reservations', []):
                            for instance in reservation.get('Instances', []):
                                instance_count += 1
                                
                                instance_id = instance.get('InstanceId', '')
                                state = instance.get('State', {}).get('Name', 'unknown')
                                
                                sys.stderr.write(f"[AWS get_all_vms] Found instance {instance_count}: {instance_id} (State: {state})\n")
                                sys.stderr.flush()
                                
                                try:
                                    # Get metrics
                                    metrics = self._get_instance_metrics(instance)
                                    
                                    # Get instance name from tags
                                    name = instance_id
                                    for tag in instance.get('Tags', []):
                                        if tag.get('Key') == 'Name':
                                            name = tag.get('Value', instance_id)
                                            break
                                    
                                    # Get instance type
                                    instance_type = instance.get('InstanceType', 'unknown')
                                    
                                    # Get availability zone (use as "node")
                                    availability_zone = instance.get('Placement', {}).get('AvailabilityZone', region)
                                    
                                    # Normalize VM data to match Proxmox structure
                                    vm_id = self._generate_instance_id(instance_id, region)
                                    
                                    vm_info = {
                                        'vmid': vm_id,
                                        'name': name,
                                        'status': self._normalize_status(state),
                                        'node': availability_zone,  # Use availability zone as "node"
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
                                        'availability_zone': availability_zone
                                    }
                                    
                                    # Add network info if available
                                    if instance.get('PublicIpAddress'):
                                        vm_info['public_ip'] = instance['PublicIpAddress']
                                    if instance.get('PrivateIpAddress'):
                                        vm_info['private_ip'] = instance['PrivateIpAddress']
                                    
                                    all_instances.append(vm_info)
                                    processed_count += 1
                                    sys.stderr.write(f"[AWS get_all_vms] Successfully processed instance: {name} ({instance_id})\n")
                                    sys.stderr.flush()
                                    
                                except Exception as e:
                                    # Log error but continue with other instances
                                    import traceback
                                    sys.stderr.write(f"[AWS get_all_vms] Error processing instance {instance_id}: {str(e)}\n")
                                    sys.stderr.write(f"[AWS get_all_vms] Traceback: {traceback.format_exc()}\n")
                                    sys.stderr.flush()
                                    continue
                    
                    sys.stderr.write(f"[AWS get_all_vms] Processed {instance_count} instance(s) from region {region}, successfully added {processed_count} to list\n")
                    sys.stderr.flush()
                
                except Exception as e:
                    # Log error but continue with other regions
                    import traceback
                    sys.stderr.write(f"[AWS get_all_vms] Error fetching instances from region {region}: {str(e)}\n")
                    sys.stderr.write(f"[AWS get_all_vms] Traceback: {traceback.format_exc()}\n")
                    sys.stderr.flush()
                    continue
            
            sys.stderr.write(f"[AWS get_all_vms] Total AWS instances found: {len(all_instances)}\n")
            sys.stderr.flush()
            return all_instances
        
        except Exception as e:
            import traceback
            error_msg = f"Error fetching instances from AWS: {str(e)}"
            sys.stderr.write(f"{error_msg}\n{traceback.format_exc()}\n")
            sys.stderr.flush()
            raise Exception(error_msg)
    
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
            except ClientError:
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
                'availability_zone': availability_zone
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
    
    def get_all_networking(self):
        """
        Fetch all networking resources (VPCs, Subnets, Security Groups, Elastic IPs).
        
        Returns:
            dict: Dictionary containing lists of networking resources
        """
        sys.stderr.write("[AWS get_all_networking] Starting networking fetch...\n")
        sys.stderr.flush()
        
        result = {
            'vpcs': [],
            'subnets': [],
            'security_groups': [],
            'elastic_ips': []
        }
        
        try:
            # Determine which regions to search
            if self.region:
                regions = [self.region]
            else:
                regions = self._get_all_regions()
            
            for region in regions:
                try:
                    sys.stderr.write(f"[AWS get_all_networking] Processing region: {region}\n")
                    sys.stderr.flush()
                    
                    ec2_client = self.session.client('ec2', region_name=region)
                    
                    # Get VPCs
                    try:
                        vpcs = ec2_client.describe_vpcs()
                        for vpc in vpcs.get('Vpcs', []):
                            vpc_info = {
                                'id': vpc['VpcId'],
                                'name': None,
                                'cidr_block': vpc.get('CidrBlock', ''),
                                'state': vpc.get('State', ''),
                                'region': region,
                                'type': 'aws',
                                'resource_type': 'vpc'
                            }
                            # Get name from tags
                            for tag in vpc.get('Tags', []):
                                if tag.get('Key') == 'Name':
                                    vpc_info['name'] = tag.get('Value')
                                    break
                            result['vpcs'].append(vpc_info)
                    except Exception as e:
                        sys.stderr.write(f"[AWS get_all_networking] Error fetching VPCs in {region}: {str(e)}\n")
                        sys.stderr.flush()
                    
                    # Get Subnets
                    try:
                        subnets = ec2_client.describe_subnets()
                        for subnet in subnets.get('Subnets', []):
                            subnet_info = {
                                'id': subnet['SubnetId'],
                                'name': None,
                                'vpc_id': subnet.get('VpcId', ''),
                                'cidr_block': subnet.get('CidrBlock', ''),
                                'availability_zone': subnet.get('AvailabilityZone', ''),
                                'state': subnet.get('State', ''),
                                'region': region,
                                'type': 'aws',
                                'resource_type': 'subnet'
                            }
                            # Get name from tags
                            for tag in subnet.get('Tags', []):
                                if tag.get('Key') == 'Name':
                                    subnet_info['name'] = tag.get('Value')
                                    break
                            result['subnets'].append(subnet_info)
                    except Exception as e:
                        sys.stderr.write(f"[AWS get_all_networking] Error fetching Subnets in {region}: {str(e)}\n")
                        sys.stderr.flush()
                    
                    # Get Security Groups
                    try:
                        security_groups = ec2_client.describe_security_groups()
                        for sg in security_groups.get('SecurityGroups', []):
                            sg_info = {
                                'id': sg['GroupId'],
                                'name': sg.get('GroupName', ''),
                                'vpc_id': sg.get('VpcId', ''),
                                'description': sg.get('Description', ''),
                                'region': region,
                                'type': 'aws',
                                'resource_type': 'security_group'
                            }
                            result['security_groups'].append(sg_info)
                    except Exception as e:
                        sys.stderr.write(f"[AWS get_all_networking] Error fetching Security Groups in {region}: {str(e)}\n")
                        sys.stderr.flush()
                    
                    # Get Elastic IPs
                    try:
                        elastic_ips = ec2_client.describe_addresses()
                        for eip in elastic_ips.get('Addresses', []):
                            eip_info = {
                                'id': eip.get('AllocationId', eip.get('PublicIp', '')),
                                'name': None,
                                'public_ip': eip.get('PublicIp', ''),
                                'private_ip': eip.get('PrivateIpAddress', ''),
                                'instance_id': eip.get('InstanceId', ''),
                                'domain': eip.get('Domain', 'vpc'),
                                'region': region,
                                'type': 'aws',
                                'resource_type': 'elastic_ip'
                            }
                            result['elastic_ips'].append(eip_info)
                    except Exception as e:
                        sys.stderr.write(f"[AWS get_all_networking] Error fetching Elastic IPs in {region}: {str(e)}\n")
                        sys.stderr.flush()
                
                except Exception as e:
                    sys.stderr.write(f"[AWS get_all_networking] Error processing region {region}: {str(e)}\n")
                    sys.stderr.flush()
                    continue
            
            sys.stderr.write(f"[AWS get_all_networking] Found {len(result['vpcs'])} VPCs, {len(result['subnets'])} Subnets, {len(result['security_groups'])} Security Groups, {len(result['elastic_ips'])} Elastic IPs\n")
            sys.stderr.flush()
            return result
        
        except Exception as e:
            import traceback
            error_msg = f"Error fetching networking resources from AWS: {str(e)}"
            sys.stderr.write(f"{error_msg}\n{traceback.format_exc()}\n")
            sys.stderr.flush()
            raise Exception(error_msg)
    
    def get_all_storage(self):
        """
        Fetch all S3 buckets.
        
        Returns:
            dict: Dictionary containing list of S3 buckets
        """
        sys.stderr.write("[AWS get_all_storage] Starting S3 bucket fetch...\n")
        sys.stderr.flush()
        
        result = {
            'buckets': []
        }
        
        try:
            # S3 is a global service, but we can use any region for the client
            # We'll use the configured region or default to us-east-1
            s3_region = self.region if self.region else 'us-east-1'
            
            # Create S3 client
            s3_client = self.session.client('s3', region_name=s3_region)
            
            try:
                # List all buckets
                response = s3_client.list_buckets()
                
                for bucket in response.get('Buckets', []):
                    bucket_name = bucket.get('Name', '')
                    creation_date = bucket.get('CreationDate', None)
                    
                    # Get bucket location/region
                    try:
                        location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                        bucket_region = location_response.get('LocationConstraint', 'us-east-1')
                        # us-east-1 returns None, so handle that
                        if bucket_region is None:
                            bucket_region = 'us-east-1'
                    except Exception as e:
                        sys.stderr.write(f"[AWS get_all_storage] Could not get location for bucket {bucket_name}: {str(e)}\n")
                        sys.stderr.flush()
                        bucket_region = s3_region
                    
                    # Get bucket size and object count (this can be slow for large buckets)
                    # We'll try to get basic info, but won't fail if we can't
                    size_bytes = 0
                    object_count = 0
                    try:
                        # Use CloudWatch metrics or list objects (limited to first 1000)
                        # For now, we'll just get basic info
                        paginator = s3_client.get_paginator('list_objects_v2')
                        for page in paginator.paginate(Bucket=bucket_name, MaxKeys=1000):
                            if 'Contents' in page:
                                object_count += len(page['Contents'])
                                for obj in page['Contents']:
                                    size_bytes += obj.get('Size', 0)
                    except Exception as e:
                        # If we can't get size info, continue with defaults
                        sys.stderr.write(f"[AWS get_all_storage] Could not get size info for bucket {bucket_name}: {str(e)}\n")
                        sys.stderr.flush()
                    
                    bucket_info = {
                        'id': bucket_name,
                        'name': bucket_name,
                        'region': bucket_region,
                        'creation_date': creation_date.isoformat() if creation_date else None,
                        'size_bytes': size_bytes,
                        'object_count': object_count,
                        'type': 'aws',
                        'resource_type': 's3_bucket'
                    }
                    
                    result['buckets'].append(bucket_info)
                
                sys.stderr.write(f"[AWS get_all_storage] Found {len(result['buckets'])} S3 buckets\n")
                sys.stderr.flush()
                return result
            
            except Exception as e:
                sys.stderr.write(f"[AWS get_all_storage] Error listing S3 buckets: {str(e)}\n")
                sys.stderr.flush()
                return result
        
        except Exception as e:
            import traceback
            error_msg = f"Error fetching S3 buckets from AWS: {str(e)}"
            sys.stderr.write(f"{error_msg}\n{traceback.format_exc()}\n")
            sys.stderr.flush()
            raise Exception(error_msg)

# Global instance (lazy initialization)
_aws_client = None

def get_aws_client():
    """Get or create the global AWS client instance"""
    sys.stderr.write("[AWS Client] get_aws_client() called\n")
    sys.stderr.flush()
    
    global _aws_client
    if _aws_client is None:
        sys.stderr.write("[AWS Client] Initializing new AWS client...\n")
        sys.stderr.flush()
        try:
            _aws_client = AWSClient()
            sys.stderr.write("[AWS Client] AWS client initialized successfully\n")
            sys.stderr.flush()
        except ValueError as e:
            # If AWS credentials are not configured, return None
            # This allows graceful degradation
            error_msg = f"[AWS Client] Not available (missing credentials): {str(e)}"
            sys.stderr.write(f"{error_msg}\n")
            sys.stderr.flush()
            return None
        except ImportError as e:
            # If boto3 is not installed
            error_msg = f"[AWS Client] Not available (boto3 not installed): {str(e)}"
            sys.stderr.write(f"{error_msg}\n")
            sys.stderr.flush()
            return None
        except Exception as e:
            # Catch any other initialization errors
            import traceback
            error_msg = f"[AWS Client] Initialization failed: {str(e)}"
            traceback_str = traceback.format_exc()
            sys.stderr.write(f"{error_msg}\n{traceback_str}\n")
            sys.stderr.flush()
            return None
    else:
        sys.stderr.write("[AWS Client] Using existing AWS client instance\n")
        sys.stderr.flush()
    return _aws_client
