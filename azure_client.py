"""
Azure API Client Module
Handles connection to Azure Compute API using Azure SDK.
"""
import os
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.core.exceptions import AzureError
from dotenv import load_dotenv
from datetime import datetime, timezone

# Load environment variables
load_dotenv()

class AzureClient:
    """Client for interacting with Azure Compute API"""
    
    def __init__(self):
        """Initialize Azure API connection using environment variables"""
        import sys
        sys.stderr.write("[Azure Client] Initializing AzureClient...\n")
        sys.stderr.flush()
        
        self.client_id = os.getenv('AZURE_CLIENT_ID', '').strip()
        self.client_secret = os.getenv('AZURE_CLIENT_SECRET', '').strip()
        self.tenant_id = os.getenv('AZURE_TENANT_ID', '').strip()
        self.subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID', '').strip()
        
        sys.stderr.write(f"[Azure Client] Environment check - CLIENT_ID: {'SET' if self.client_id else 'NOT SET'}, TENANT_ID: {'SET' if self.tenant_id else 'NOT SET'}, SECRET: {'SET' if self.client_secret else 'NOT SET'}\n")
        sys.stderr.flush()
        
        if not all([self.client_id, self.client_secret, self.tenant_id]):
            error_msg = (
                "Missing required Azure environment variables. "
                "Please set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID"
            )
            sys.stderr.write(f"[Azure Client] ERROR: {error_msg}\n")
            sys.stderr.flush()
            raise ValueError(error_msg)
        
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
    
    def get_all_vms(self):
        """
        Fetch all VMs from all subscriptions and resource groups.
        
        Returns:
            list: List of dictionaries containing VM information
        """
        import sys
        sys.stderr.write("[Azure get_all_vms] Starting VM fetch...\n")
        sys.stderr.flush()
        
        all_vms = []
        
        try:
            subscriptions = []
            
            # If subscription_id is set, use only that subscription
            if self.subscription_id:
                subscriptions = [self.subscription_id]
                sys.stderr.write(f"[Azure get_all_vms] Using configured subscription: {self.subscription_id}\n")
                sys.stderr.flush()
            else:
                # Otherwise, list all subscriptions
                try:
                    sys.stderr.write("[Azure get_all_vms] Listing all subscriptions...\n")
                    sys.stderr.flush()
                    subscription_list = self.resource_client.subscriptions.list()
                    subscriptions = [sub.subscription_id for sub in subscription_list]
                    sys.stderr.write(f"[Azure get_all_vms] Found {len(subscriptions)} subscription(s)\n")
                    for i, sub_id in enumerate(subscriptions[:5]):  # Show first 5
                        sys.stderr.write(f"[Azure get_all_vms]   Subscription {i+1}: {sub_id}\n")
                    if len(subscriptions) > 5:
                        sys.stderr.write(f"[Azure get_all_vms]   ... and {len(subscriptions) - 5} more\n")
                    sys.stderr.flush()
                except Exception as e:
                    import traceback
                    sys.stderr.write(f"[Azure get_all_vms] Error: Could not list subscriptions: {str(e)}\n")
                    sys.stderr.write(f"[Azure get_all_vms] Traceback: {traceback.format_exc()}\n")
                    sys.stderr.flush()
                    return all_vms
            
            if not subscriptions:
                sys.stderr.write("[Azure get_all_vms] WARNING: No subscriptions found!\n")
                sys.stderr.flush()
                return all_vms
            
            # Iterate through subscriptions
            for subscription_id in subscriptions:
                try:
                    import sys
                    sys.stderr.write(f"[Azure get_all_vms] Processing subscription: {subscription_id}\n")
                    sys.stderr.flush()
                    # Create compute client for this subscription
                    compute_client = ComputeManagementClient(
                        self.credential,
                        subscription_id
                    )
                    
                    # List all VMs in this subscription
                    sys.stderr.write(f"[Azure get_all_vms] Listing VMs in subscription {subscription_id}...\n")
                    sys.stderr.flush()
                    vm_list = compute_client.virtual_machines.list_all()
                    vm_count = 0
                    processed_count = 0
                    
                    for vm in vm_list:
                        vm_count += 1
                        
                        # Extract resource group name from VM ID
                        # ID format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}
                        resource_group_name = None
                        if vm.id:
                            parts = vm.id.split('/')
                            try:
                                rg_index = parts.index('resourceGroups')
                                if rg_index + 1 < len(parts):
                                    resource_group_name = parts[rg_index + 1]
                            except ValueError:
                                pass
                        
                        if not resource_group_name:
                            sys.stderr.write(f"[Azure get_all_vms] WARNING: Could not extract resource group from VM {vm.name} (ID: {vm.id})\n")
                            sys.stderr.flush()
                            continue
                        
                        sys.stderr.write(f"[Azure get_all_vms] Found VM {vm_count}: {vm.name} (RG: {resource_group_name})\n")
                        sys.stderr.flush()
                        try:
                            # Get instance view to check power state
                            instance_view = compute_client.virtual_machines.instance_view(
                                resource_group_name,
                                vm.name
                            )
                            
                            # Extract power state from instance view
                            power_state = None
                            for status in instance_view.statuses:
                                if status.code and status.code.startswith('PowerState/'):
                                    power_state = status.code
                                    break
                            
                            # Get metrics
                            metrics = self._get_vm_metrics_with_client(vm, compute_client, resource_group_name)
                            
                            # Normalize VM data to match Proxmox structure
                            vm_id = self._generate_vm_id(resource_group_name, vm.name)
                            
                            vm_info = {
                                'vmid': vm_id,
                                'name': vm.name,
                                'status': self._normalize_status(power_state),
                                'node': resource_group_name,  # Use resource group as "node"
                                'type': 'azure',
                                'cpu': metrics['cpu'],
                                'mem': metrics['mem'],
                                'maxmem': metrics['maxmem'],
                                'disk': metrics['disk'],
                                'maxdisk': metrics['maxdisk'],
                                'uptime': metrics['uptime'],
                                'subscription_id': subscription_id,
                                'resource_group': resource_group_name,
                                'location': vm.location if hasattr(vm, 'location') else None
                            }
                            
                            # Add hardware profile info if available
                            if vm.hardware_profile:
                                vm_info['vm_size'] = vm.hardware_profile.vm_size
                            
                            all_vms.append(vm_info)
                            processed_count += 1
                            sys.stderr.write(f"[Azure get_all_vms] Successfully processed VM: {vm.name}\n")
                            sys.stderr.flush()
                            
                        except Exception as e:
                            # Log error but continue with other VMs
                            import traceback
                            import sys
                            rg_name = resource_group_name if 'resource_group_name' in locals() else 'unknown'
                            sys.stderr.write(f"[Azure get_all_vms] Error processing VM {vm.name} in {rg_name}: {str(e)}\n")
                            sys.stderr.write(f"[Azure get_all_vms] Traceback: {traceback.format_exc()}\n")
                            sys.stderr.flush()
                            continue
                    
                    sys.stderr.write(f"[Azure get_all_vms] Processed {vm_count} VM(s) from subscription {subscription_id}, successfully added {processed_count} to list\n")
                    sys.stderr.flush()
                
                except Exception as e:
                    # Log error but continue with other subscriptions
                    import traceback
                    import sys
                    sys.stderr.write(f"[Azure get_all_vms] Error fetching VMs from subscription {subscription_id}: {str(e)}\n")
                    sys.stderr.write(f"[Azure get_all_vms] Traceback: {traceback.format_exc()}\n")
                    sys.stderr.flush()
                    continue
            
            import sys
            sys.stderr.write(f"[Azure get_all_vms] Total Azure VMs found: {len(all_vms)}\n")
            sys.stderr.flush()
            return all_vms
        
        except Exception as e:
            import traceback
            error_msg = f"Error fetching VMs from Azure: {str(e)}"
            print(error_msg)
            print(f"Traceback: {traceback.format_exc()}")
            raise Exception(error_msg)
    
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
                'subscription_id': subscription_id
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
        import sys
        sys.stderr.write("[Azure get_all_networking] Starting networking fetch...\n")
        sys.stderr.flush()
        
        result = {
            'vnets': [],
            'subnets': [],
            'nsgs': [],
            'public_ips': []
        }
        
        try:
            subscriptions = []
            
            if self.subscription_id:
                subscriptions = [self.subscription_id]
            else:
                try:
                    subscription_list = self.resource_client.subscriptions.list()
                    subscriptions = [sub.subscription_id for sub in subscription_list]
                except Exception as e:
                    sys.stderr.write(f"[Azure get_all_networking] Error listing subscriptions: {str(e)}\n")
                    sys.stderr.flush()
                    return result
            
            for subscription_id in subscriptions:
                try:
                    network_client = NetworkManagementClient(self.credential, subscription_id)
                    resource_client = ResourceManagementClient(self.credential, subscription_id)
                    
                    # Get all resource groups
                    resource_groups = resource_client.resource_groups.list()
                    
                    for rg in resource_groups:
                        rg_name = rg.name
                        
                        try:
                            # Get Virtual Networks
                            vnets = network_client.virtual_networks.list(rg_name)
                            for vnet in vnets:
                                address_space = []
                                if vnet.address_space and vnet.address_space.address_prefixes:
                                    address_space = list(vnet.address_space.address_prefixes)
                                
                                vnet_info = {
                                    'id': vnet.id,
                                    'name': vnet.name,
                                    'resource_group': rg_name,
                                    'location': vnet.location,
                                    'address_space': address_space,
                                    'subscription_id': subscription_id,
                                    'type': 'azure',
                                    'resource_type': 'vnet'
                                }
                                result['vnets'].append(vnet_info)
                            
                            # Get Subnets
                            for vnet in network_client.virtual_networks.list(rg_name):
                                subnets = network_client.subnets.list(rg_name, vnet.name)
                                for subnet in subnets:
                                    subnet_info = {
                                        'id': subnet.id,
                                        'name': subnet.name,
                                        'vnet_name': vnet.name,
                                        'resource_group': rg_name,
                                        'address_prefix': subnet.address_prefix,
                                        'subscription_id': subscription_id,
                                        'type': 'azure',
                                        'resource_type': 'subnet'
                                    }
                                    result['subnets'].append(subnet_info)
                            
                            # Get Network Security Groups
                            nsgs = network_client.network_security_groups.list(rg_name)
                            for nsg in nsgs:
                                nsg_info = {
                                    'id': nsg.id,
                                    'name': nsg.name,
                                    'resource_group': rg_name,
                                    'location': nsg.location,
                                    'subscription_id': subscription_id,
                                    'type': 'azure',
                                    'resource_type': 'nsg'
                                }
                                result['nsgs'].append(nsg_info)
                            
                            # Get Public IP Addresses
                            public_ips = network_client.public_ip_addresses.list(rg_name)
                            for pip in public_ips:
                                pip_info = {
                                    'id': pip.id,
                                    'name': pip.name,
                                    'resource_group': rg_name,
                                    'location': pip.location,
                                    'ip_address': pip.ip_address if hasattr(pip, 'ip_address') else None,
                                    'allocation_method': pip.public_ip_allocation_method.value if hasattr(pip, 'public_ip_allocation_method') and pip.public_ip_allocation_method else None,
                                    'subscription_id': subscription_id,
                                    'type': 'azure',
                                    'resource_type': 'public_ip'
                                }
                                result['public_ips'].append(pip_info)
                        
                        except Exception as e:
                            sys.stderr.write(f"[Azure get_all_networking] Error processing RG {rg_name}: {str(e)}\n")
                            sys.stderr.flush()
                            continue
                
                except Exception as e:
                    sys.stderr.write(f"[Azure get_all_networking] Error processing subscription {subscription_id}: {str(e)}\n")
                    sys.stderr.flush()
                    continue
            
            sys.stderr.write(f"[Azure get_all_networking] Found {len(result['vnets'])} VNets, {len(result['subnets'])} Subnets, {len(result['nsgs'])} NSGs, {len(result['public_ips'])} Public IPs\n")
            sys.stderr.flush()
            return result
        
        except Exception as e:
            import traceback
            error_msg = f"Error fetching networking resources from Azure: {str(e)}"
            sys.stderr.write(f"{error_msg}\n{traceback.format_exc()}\n")
            sys.stderr.flush()
            raise Exception(error_msg)

# Global instance (lazy initialization)
_azure_client = None

def get_azure_client():
    """Get or create the global Azure client instance"""
    import sys
    sys.stderr.write("[Azure Client] get_azure_client() called\n")
    sys.stderr.flush()
    
    global _azure_client
    if _azure_client is None:
        sys.stderr.write("[Azure Client] Initializing new Azure client...\n")
        sys.stderr.flush()
        try:
            _azure_client = AzureClient()
            sys.stderr.write("[Azure Client] Azure client initialized successfully\n")
            sys.stderr.flush()
        except ValueError as e:
            # If Azure credentials are not configured, return None
            # This allows graceful degradation
            error_msg = f"[Azure Client] Not available (missing credentials): {str(e)}"
            sys.stderr.write(f"{error_msg}\n")
            sys.stderr.flush()
            return None
        except Exception as e:
            # Catch any other initialization errors
            import traceback
            error_msg = f"[Azure Client] Initialization failed: {str(e)}"
            traceback_str = traceback.format_exc()
            sys.stderr.write(f"{error_msg}\n{traceback_str}\n")
            sys.stderr.flush()
            return None
    else:
        sys.stderr.write("[Azure Client] Using existing Azure client instance\n")
        sys.stderr.flush()
    return _azure_client
