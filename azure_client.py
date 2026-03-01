"""
Azure API Client Module
Handles connection to Azure Compute API using Azure SDK.
"""
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Azure SDK packages are heavy — only load them when a client is actually
# instantiated, not at module import time.
def _ensure_sdk() -> None:
    """Inject Azure SDK classes into module globals on first call. No-op thereafter."""
    if 'ClientSecretCredential' in globals():
        return
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.resource import ResourceManagementClient
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.storage import StorageManagementClient
        from azure.core.exceptions import AzureError
    except ImportError as exc:
        raise ImportError(
            "Azure SDK packages are not installed. Run: "
            "pip install azure-identity azure-mgmt-compute azure-mgmt-resource "
            "azure-mgmt-network azure-mgmt-storage azure-storage-blob"
        ) from exc
    globals().update({
        'ClientSecretCredential':   ClientSecretCredential,
        'ComputeManagementClient':  ComputeManagementClient,
        'ResourceManagementClient': ResourceManagementClient,
        'NetworkManagementClient':  NetworkManagementClient,
        'StorageManagementClient':  StorageManagementClient,
        'AzureError':               AzureError,
    })

# Load environment variables
load_dotenv()

class AzureClient:
    """Client for interacting with Azure Compute API"""
    
    def __init__(self):
        """Initialize Azure API connection using environment variables"""
        _ensure_sdk()
        self.client_id       = os.getenv('AZURE_CLIENT_ID', '').strip()
        self.client_secret   = os.getenv('AZURE_CLIENT_SECRET', '').strip()
        self.tenant_id       = os.getenv('AZURE_TENANT_ID', '').strip()
        self.subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID', '').strip()

        if not all([self.client_id, self.client_secret, self.tenant_id]):
            raise ValueError(
                "Missing required Azure environment variables: "
                "AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID"
            )
        
        # Create credential for authentication
        self.credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )
        
        # Create compute management client
        self.compute_client = ComputeManagementClient(
            self.credential,
            self.subscription_id if self.subscription_id else None
        )
        
        # Create resource management client for listing subscriptions
        self.resource_client = ResourceManagementClient(
            self.credential,
            self.subscription_id if self.subscription_id else None
        )
        
        # Create network management client
        self.network_client = NetworkManagementClient(
            self.credential,
            self.subscription_id if self.subscription_id else None
        )
        
        # Create storage management client
        self.storage_client = StorageManagementClient(
            self.credential,
            self.subscription_id if self.subscription_id else None
        )
    
    def _normalize_status(self, power_state):
        """
        Normalize Azure VM power state to match Proxmox status format.
        
        Args:
            power_state: Azure VM power state (e.g., 'PowerState/running', 'PowerState/deallocated')
            
        Returns:
            str: Normalized status ('running', 'stopped', etc.)
        """
        if not power_state:
            return 'unknown'
        
        # Azure power states are in format 'PowerState/state'
        state = power_state.split('/')[-1].lower() if '/' in power_state else power_state.lower()
        
        status_map = {
            'running': 'running',
            'stopped': 'stopped',
            'deallocated': 'stopped',
            'deallocating': 'stopped',
            'starting': 'running',
            'stopping': 'stopped',
        }
        
        return status_map.get(state, 'unknown')
    
    def _extract_tags(self, resource):
        """
        Extract tags from an Azure resource and convert to array format.
        Azure tags are stored as a dictionary where keys are tag names and values are tag values.
        
        Args:
            resource: Azure resource object with tags attribute
            
        Returns:
            list: List of dictionaries with 'key' and 'value' for key-value pairs
        """
        tags = []
        if hasattr(resource, 'tags') and resource.tags:
            # Azure tags are a dictionary, convert to list of key-value objects
            for key, value in resource.tags.items():
                tags.append({'key': key, 'value': value})
        return tags
    
    def _generate_vm_id(self, resource_group, vm_name):
        """
        Generate a unique VM ID for Azure VMs.
        
        Args:
            resource_group: Azure resource group name
            vm_name: VM name
            
        Returns:
            str: Unique VM ID
        """
        return f"azure-{resource_group}-{vm_name}"
    
    def _parse_vm_id(self, vm_id):
        """
        Parse Azure VM ID back to resource group and VM name.
        
        Args:
            vm_id: Azure VM ID (format: azure-{resource_group}-{vm_name})
            
        Returns:
            tuple: (resource_group, vm_name)
        """
        if not vm_id.startswith('azure-'):
            raise ValueError(f"Invalid Azure VM ID format: {vm_id}")
        
        parts = vm_id[6:].split('-', 1)  # Remove 'azure-' prefix
        if len(parts) != 2:
            raise ValueError(f"Invalid Azure VM ID format: {vm_id}")
        
        return parts[0], parts[1]
    
    def _get_vm_metrics(self, vm, resource_group_name):
        """
        Extract metrics from Azure VM instance view.
        Uses the default compute_client.
        
        Args:
            vm: Azure VM object
            resource_group_name: Resource group name
            
        Returns:
            dict: Metrics including CPU, memory, disk usage
        """
        return self._get_vm_metrics_with_client(vm, self.compute_client, resource_group_name)
    
    def _get_vm_metrics_with_client(self, vm, compute_client, resource_group_name):
        """
        Extract metrics from Azure VM instance view.
        
        Args:
            vm: Azure VM object
            compute_client: ComputeManagementClient instance
            resource_group_name: Resource group name (extracted from VM ID)
            
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
            # Get VM instance view for metrics
            instance_view = compute_client.virtual_machines.instance_view(
                resource_group_name,
                vm.name
            )
            
            # Extract memory information from hardware profile
            if vm.hardware_profile:
                # Memory is in MB, convert to bytes
                max_memory_mb = vm.hardware_profile.vm_size
                # VM size doesn't directly give memory, need to look it up
                # For now, use a default or try to get from disk size or config
                metrics['maxmem'] = 0  # Will be set from disk size or config
            
            # Extract disk information
            if vm.storage_profile and vm.storage_profile.os_disk:
                # Get disk size from OS disk
                disk_name = vm.storage_profile.os_disk.name
                try:
                    disk = compute_client.disks.get(
                        resource_group_name,
                        disk_name
                    )
                    if disk:
                        metrics['maxdisk'] = disk.disk_size_gb * 1024 * 1024 * 1024  # Convert GB to bytes
                        metrics['disk'] = metrics['maxdisk']  # Approximate, actual usage would need metrics API
                except:
                    pass
            
            # Calculate uptime from instance view
            if instance_view.statuses:
                for status in instance_view.statuses:
                    if status.code and status.code.startswith('PowerState/'):
                        # Try to get time from status
                        pass
            
            # Get CPU percentage from instance view (if available)
            # Azure doesn't provide real-time CPU in instance view, would need metrics API
            
        except Exception as e:
            # If we can't get metrics, return defaults
            print(f"Warning: Could not get metrics for VM {vm.name}: {str(e)}")
        
        return metrics
    
    def _process_vm(self, vm, resource_group_name, compute_client, subscription_id):
        """Fetch instance view + metrics for a single VM. Runs in a thread pool."""
        instance_view = compute_client.virtual_machines.instance_view(
            resource_group_name, vm.name
        )
        power_state = None
        for status in instance_view.statuses:
            if status.code and status.code.startswith('PowerState/'):
                power_state = status.code
                break

        metrics = self._get_vm_metrics_with_client(vm, compute_client, resource_group_name)
        tags    = self._extract_tags(vm)
        vm_id   = self._generate_vm_id(resource_group_name, vm.name)

        vm_info = {
            'vmid':            vm_id,
            'name':            vm.name,
            'status':          self._normalize_status(power_state),
            'node':            resource_group_name,
            'type':            'azure',
            'cpu':             metrics['cpu'],
            'mem':             metrics['mem'],
            'maxmem':          metrics['maxmem'],
            'disk':            metrics['disk'],
            'maxdisk':         metrics['maxdisk'],
            'uptime':          metrics['uptime'],
            'subscription_id': subscription_id,
            'resource_group':  resource_group_name,
            'location':        getattr(vm, 'location', None),
            'tags':            tags,
        }
        if vm.hardware_profile:
            vm_info['vm_size'] = vm.hardware_profile.vm_size
        return vm_info

    def get_all_vms(self):
        """
        Fetch all VMs from all subscriptions and resource groups.

        Returns:
            list: List of dictionaries containing VM information
        """
        logger.info("[Azure] Starting VM fetch")
        all_vms = []

        try:
            if self.subscription_id:
                subscriptions = [self.subscription_id]
            else:
                try:
                    subscriptions = [
                        sub.subscription_id
                        for sub in self.resource_client.subscriptions.list()
                    ]
                    logger.info("[Azure] Found %d subscription(s)", len(subscriptions))
                except Exception as e:
                    logger.error("[Azure] Could not list subscriptions: %s", e)
                    return all_vms

            if not subscriptions:
                logger.warning("[Azure] No subscriptions found")
                return all_vms

            # Phase 1: list VMs (fast — just metadata, no extra API calls)
            work_items = []
            for subscription_id in subscriptions:
                try:
                    compute_client = ComputeManagementClient(self.credential, subscription_id)
                    for vm in compute_client.virtual_machines.list_all():
                        resource_group_name = None
                        if vm.id:
                            parts = vm.id.split('/')
                            try:
                                idx = parts.index('resourceGroups')
                                resource_group_name = parts[idx + 1]
                            except (ValueError, IndexError):
                                pass
                        if resource_group_name:
                            work_items.append((vm, resource_group_name, compute_client, subscription_id))
                        else:
                            logger.warning("[Azure] Could not extract resource group from VM %s", vm.name)
                except Exception as e:
                    logger.error("[Azure] Error listing VMs in subscription %s: %s", subscription_id, e)

            logger.info("[Azure] Fetching details for %d VM(s) in parallel", len(work_items))

            # Phase 2: parallelize instance_view + metrics (the slow part)
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(self._process_vm, vm, rg, cc, sub): vm.name
                    for vm, rg, cc, sub in work_items
                }
                for future in as_completed(futures):
                    vm_name = futures[future]
                    try:
                        all_vms.append(future.result())
                    except Exception as e:
                        logger.error("[Azure] Error processing VM %s: %s", vm_name, e)

            logger.info("[Azure] Total Azure VMs found: %d", len(all_vms))
            return all_vms

        except Exception as e:
            import traceback
            raise Exception(f"Error fetching VMs from Azure: {e}") from e
    
    def _find_vm_subscription(self, resource_group, vm_name):
        """
        Find which subscription a VM belongs to by searching across subscriptions.
        
        Args:
            resource_group: Resource group name
            vm_name: VM name
            
        Returns:
            str: Subscription ID where the VM is located
        """
        subscriptions = []
        
        if self.subscription_id:
            subscriptions = [self.subscription_id]
        else:
            try:
                subscription_list = self.resource_client.subscriptions.list()
                subscriptions = [sub.subscription_id for sub in subscription_list]
            except Exception as e:
                raise Exception(f"Could not list subscriptions: {str(e)}")
        
        for subscription_id in subscriptions:
            try:
                compute_client = ComputeManagementClient(
                    self.credential,
                    subscription_id
                )
                # Try to get the VM
                vm = compute_client.virtual_machines.get(resource_group, vm_name)
                return subscription_id
            except Exception:
                continue
        
        raise ValueError(f"VM {vm_name} in resource group {resource_group} not found in any subscription")
    
    def get_vm_details(self, vm_id):
        """
        Get detailed information about a specific VM.
        
        Args:
            vm_id: Azure VM ID (format: azure-{resource_group}-{vm_name})
            
        Returns:
            dict: Detailed VM information
        """
        try:
            resource_group, vm_name = self._parse_vm_id(vm_id)
            
            # Find which subscription this VM belongs to
            subscription_id = self._find_vm_subscription(resource_group, vm_name)
            
            # Create compute client for this subscription
            compute_client = ComputeManagementClient(
                self.credential,
                subscription_id
            )
            
            # Get VM
            vm = compute_client.virtual_machines.get(
                resource_group,
                vm_name
            )
            
            # Get instance view
            instance_view = compute_client.virtual_machines.instance_view(
                resource_group,
                vm_name
            )
            
            # Extract power state
            power_state = None
            for status in instance_view.statuses:
                if status.code and status.code.startswith('PowerState/'):
                    power_state = status.code
                    break
            
            # Get metrics (need to pass compute_client and resource_group)
            metrics = self._get_vm_metrics_with_client(vm, compute_client, resource_group)
            
            # Extract tags
            tags = self._extract_tags(vm)
            
            # Build detailed VM info
            vm_details = {
                'vmid': vm_id,
                'name': vm.name,
                'status': self._normalize_status(power_state),
                'node': resource_group,
                'type': 'azure',
                'cpu': metrics['cpu'],
                'mem': metrics['mem'],
                'maxmem': metrics['maxmem'],
                'disk': metrics['disk'],
                'maxdisk': metrics['maxdisk'],
                'uptime': metrics['uptime'],
                'resource_group': resource_group,
                'location': vm.location,
                'subscription_id': subscription_id,
                'tags': tags
            }
            
            # Add hardware profile info
            if vm.hardware_profile:
                vm_details['vm_size'] = vm.hardware_profile.vm_size
            
            # Add network info
            if vm.network_profile and vm.network_profile.network_interfaces:
                vm_details['network_interfaces'] = [
                    nic.id for nic in vm.network_profile.network_interfaces
                ]
            
            return vm_details
        
        except ValueError:
            raise
        except Exception as e:
            raise Exception(f"Error fetching VM details: {str(e)}")
    
    def start_vm(self, vm_id):
        """
        Start a virtual machine.
        
        Args:
            vm_id: Azure VM ID (format: azure-{resource_group}-{vm_name})
            
        Returns:
            dict: Operation result
        """
        try:
            resource_group, vm_name = self._parse_vm_id(vm_id)
            
            # Find which subscription this VM belongs to
            subscription_id = self._find_vm_subscription(resource_group, vm_name)
            
            # Create compute client for this subscription
            compute_client = ComputeManagementClient(
                self.credential,
                subscription_id
            )
            
            # Start the VM (async operation)
            async_result = compute_client.virtual_machines.begin_start(
                resource_group,
                vm_name
            )
            
            # Wait for the operation to complete
            async_result.wait()
            
            return {
                'status': 'success',
                'message': f'VM {vm_name} started successfully'
            }
        
        except ValueError:
            raise
        except Exception as e:
            raise Exception(f"Error starting VM {vm_id}: {str(e)}")
    
    def stop_vm(self, vm_id):
        """
        Stop a virtual machine.
        
        Args:
            vm_id: Azure VM ID (format: azure-{resource_group}-{vm_name})
            
        Returns:
            dict: Operation result
        """
        try:
            resource_group, vm_name = self._parse_vm_id(vm_id)
            
            # Find which subscription this VM belongs to
            subscription_id = self._find_vm_subscription(resource_group, vm_name)
            
            # Create compute client for this subscription
            compute_client = ComputeManagementClient(
                self.credential,
                subscription_id
            )
            
            # Stop the VM (async operation)
            # Using deallocate=False to keep VM allocated (just stop, not deallocate)
            async_result = compute_client.virtual_machines.begin_power_off(
                resource_group,
                vm_name,
                skip_shutdown=False  # Graceful shutdown
            )
            
            # Wait for the operation to complete
            async_result.wait()
            
            return {
                'status': 'success',
                'message': f'VM {vm_name} stopped successfully'
            }
        
        except ValueError:
            raise
        except Exception as e:
            raise Exception(f"Error stopping VM {vm_id}: {str(e)}")
    
    def get_all_networking(self):
        """
        Fetch all networking resources (VNets, Subnets, NSGs, Public IPs).

        Returns:
            dict: Dictionary containing lists of networking resources
        """
        logger.info("[Azure] Starting networking fetch")
        result = {'vnets': [], 'subnets': [], 'nsgs': [], 'public_ips': []}

        try:
            if self.subscription_id:
                subscriptions = [self.subscription_id]
            else:
                try:
                    subscriptions = [
                        sub.subscription_id
                        for sub in self.resource_client.subscriptions.list()
                    ]
                except Exception as e:
                    logger.error("[Azure] Error listing subscriptions: %s", e)
                    return result

            for subscription_id in subscriptions:
                try:
                    network_client  = NetworkManagementClient(self.credential, subscription_id)
                    resource_client = ResourceManagementClient(self.credential, subscription_id)

                    for rg in resource_client.resource_groups.list():
                        rg_name = rg.name
                        try:
                            # Materialise once — used for both vnets and subnets
                            vnet_list = list(network_client.virtual_networks.list(rg_name))

                            for vnet in vnet_list:
                                address_space = []
                                if vnet.address_space and vnet.address_space.address_prefixes:
                                    address_space = list(vnet.address_space.address_prefixes)
                                result['vnets'].append({
                                    'id':              vnet.id,
                                    'name':            vnet.name,
                                    'resource_group':  rg_name,
                                    'location':        vnet.location,
                                    'address_space':   address_space,
                                    'subscription_id': subscription_id,
                                    'type':            'azure',
                                    'resource_type':   'vnet',
                                    'tags':            self._extract_tags(vnet),
                                })

                            # Reuse vnet_list — no second API call
                            for vnet in vnet_list:
                                for subnet in network_client.subnets.list(rg_name, vnet.name):
                                    result['subnets'].append({
                                        'id':              subnet.id,
                                        'name':            subnet.name,
                                        'vnet_name':       vnet.name,
                                        'resource_group':  rg_name,
                                        'address_prefix':  subnet.address_prefix,
                                        'subscription_id': subscription_id,
                                        'type':            'azure',
                                        'resource_type':   'subnet',
                                        'tags':            self._extract_tags(subnet),
                                    })

                            for nsg in network_client.network_security_groups.list(rg_name):
                                result['nsgs'].append({
                                    'id':              nsg.id,
                                    'name':            nsg.name,
                                    'resource_group':  rg_name,
                                    'location':        nsg.location,
                                    'subscription_id': subscription_id,
                                    'type':            'azure',
                                    'resource_type':   'nsg',
                                    'tags':            self._extract_tags(nsg),
                                })

                            for pip in network_client.public_ip_addresses.list(rg_name):
                                alloc = None
                                if hasattr(pip, 'public_ip_allocation_method') and pip.public_ip_allocation_method:
                                    alloc = pip.public_ip_allocation_method.value
                                result['public_ips'].append({
                                    'id':                pip.id,
                                    'name':              pip.name,
                                    'resource_group':    rg_name,
                                    'location':          pip.location,
                                    'ip_address':        getattr(pip, 'ip_address', None),
                                    'allocation_method': alloc,
                                    'subscription_id':   subscription_id,
                                    'type':              'azure',
                                    'resource_type':     'public_ip',
                                    'tags':              self._extract_tags(pip),
                                })

                        except Exception as e:
                            logger.error("[Azure] Error processing RG %s: %s", rg_name, e)
                            continue

                except Exception as e:
                    logger.error("[Azure] Error processing subscription %s: %s", subscription_id, e)
                    continue

            logger.info(
                "[Azure] Networking: %d VNets, %d Subnets, %d NSGs, %d Public IPs",
                len(result['vnets']), len(result['subnets']),
                len(result['nsgs']), len(result['public_ips']),
            )
            return result

        except Exception as e:
            raise Exception(f"Error fetching networking resources from Azure: {e}") from e
    
    def get_all_storage(self):
        """
        Fetch all Blob Storage accounts and containers.

        Returns:
            dict: Dictionary containing lists of storage accounts and containers
        """
        logger.info("[Azure] Starting storage fetch")
        result = {'storage_accounts': [], 'containers': []}

        try:
            if self.subscription_id:
                subscriptions = [self.subscription_id]
            else:
                try:
                    subscriptions = [
                        sub.subscription_id
                        for sub in self.resource_client.subscriptions.list()
                    ]
                except Exception as e:
                    logger.error("[Azure] Error listing subscriptions: %s", e)
                    return result

            for subscription_id in subscriptions:
                try:
                    storage_client  = StorageManagementClient(self.credential, subscription_id)
                    resource_client = ResourceManagementClient(self.credential, subscription_id)

                    for rg in resource_client.resource_groups.list():
                        rg_name = rg.name
                        try:
                            for account in storage_client.storage_accounts.list_by_resource_group(rg_name):
                                if account.kind not in ['BlobStorage', 'StorageV2', 'Storage']:
                                    continue

                                account_info = {
                                    'id':              account.id,
                                    'name':            account.name,
                                    'resource_group':  rg_name,
                                    'location':        account.location,
                                    'kind':            account.kind,
                                    'sku':             account.sku.name if account.sku else None,
                                    'subscription_id': subscription_id,
                                    'type':            'azure',
                                    'resource_type':   'storage_account',
                                    'tags':            self._extract_tags(account),
                                }
                                if account.primary_endpoints:
                                    account_info['primary_blob_endpoint'] = account.primary_endpoints.blob
                                    account_info['primary_file_endpoint'] = account.primary_endpoints.file
                                result['storage_accounts'].append(account_info)

                                try:
                                    from azure.storage.blob import BlobServiceClient
                                    keys = storage_client.storage_accounts.list_keys(rg_name, account.name)
                                    if keys.keys:
                                        conn = (
                                            f"DefaultEndpointsProtocol=https;"
                                            f"AccountName={account.name};"
                                            f"AccountKey={keys.keys[0].value};"
                                            f"EndpointSuffix=core.windows.net"
                                        )
                                        blob_svc = BlobServiceClient.from_connection_string(conn)
                                        for container in blob_svc.list_containers():
                                            c_info = {
                                                'id':              f"{account.name}/{container.name}",
                                                'name':            container.name,
                                                'storage_account': account.name,
                                                'resource_group':  rg_name,
                                                'public_access':   container.public_access or 'None',
                                                'subscription_id': subscription_id,
                                                'type':            'azure',
                                                'resource_type':   'blob_container',
                                                'tags':            [],
                                            }
                                            try:
                                                props = blob_svc.get_container_client(container.name).get_container_properties()
                                                c_info['last_modified'] = props.last_modified.isoformat() if props.last_modified else None
                                            except Exception:
                                                pass
                                            result['containers'].append(c_info)
                                except Exception as e:
                                    logger.error("[Azure] Error fetching containers for %s: %s", account.name, e)
                        except Exception as e:
                            logger.error("[Azure] Error processing RG %s: %s", rg_name, e)
                except Exception as e:
                    logger.error("[Azure] Error processing subscription %s: %s", subscription_id, e)

            logger.info(
                "[Azure] Storage: %d accounts, %d containers",
                len(result['storage_accounts']), len(result['containers']),
            )
            return result

        except Exception as e:
            raise Exception(f"Error fetching storage resources from Azure: {e}") from e

# Global instance (lazy initialization)
_azure_client = None
_azure_client_lock = threading.Lock()

def get_azure_client():
    """Get or create the global Azure client instance."""
    global _azure_client
    if _azure_client is None:
        with _azure_client_lock:
            if _azure_client is None:  # re-check after acquiring lock
                try:
                    _azure_client = AzureClient()
                    logger.info("[Azure Client] Initialized successfully")
                except ValueError as e:
                    logger.warning("[Azure Client] Not available: %s", e)
                    return None
                except Exception as e:
                    logger.error("[Azure Client] Initialization failed: %s", e)
                    return None
    return _azure_client
