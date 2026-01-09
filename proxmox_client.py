"""
Proxmox API Client Module
Handles connection to Proxmox VE API using direct HTTP requests.
"""
import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class ProxmoxClient:
    """Client for interacting with Proxmox VE API using direct HTTP requests"""
    
    def __init__(self):
        """Initialize Proxmox API connection using environment variables"""
        self.host = os.getenv('PROXMOX_HOST', '').strip()
        self.token_id = os.getenv('PROXMOX_TOKEN_ID', '').strip()
        self.token_secret = os.getenv('PROXMOX_TOKEN_SECRET', '').strip()
        
        if not all([self.host, self.token_id, self.token_secret]):
            raise ValueError(
                "Missing required Proxmox environment variables. "
                "Please set PROXMOX_HOST, PROXMOX_TOKEN_ID, and PROXMOX_TOKEN_SECRET"
            )
        
        # Construct base URL (Proxmox API typically uses port 8006)
        if ':' in self.host and not self.host.startswith('http'):
            # Host already includes port
            self.base_url = f"https://{self.host}/api2/json"
        elif self.host.startswith('http'):
            # Full URL provided
            base = self.host.rstrip('/')
            self.base_url = f"{base}/api2/json"
        else:
            # Just hostname/IP, default to port 8006
            self.base_url = f"https://{self.host}:8006/api2/json"
        
        # Proxmox API token authentication uses custom header format:
        # Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET
        # Ensure token_id is in the correct format (user@realm!tokenid)
        if '!' not in self.token_id:
            raise ValueError(
                f"PROXMOX_TOKEN_ID must be in format 'user@realm!tokenid', got: {self.token_id}"
            )
        
        # Construct the authentication header
        # Format: PVEAPIToken=user@realm!tokenid=secret
        self.auth_header = f"PVEAPIToken={self.token_id}={self.token_secret}"
        
        # Create session with authentication header
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': self.auth_header
        })
        self.session.verify = False  # Set to True in production with valid SSL certificates
        
        # Suppress SSL warnings in development
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def _make_request(self, method, endpoint, params=None, data=None):
        """
        Make an HTTP request to the Proxmox API.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (e.g., '/nodes')
            params: Optional query parameters
            data: Optional POST data
            
        Returns:
            dict: JSON response data
        """
        url = f"{self.base_url}{endpoint}"
        
        try:
            # Make the request
            response = self.session.request(method, url, params=params, json=data, timeout=10)
            
            # Check for authentication errors first
            if response.status_code == 401:
                error_msg = "Unauthorized"
                error_details = {}
                
                # Try to parse JSON error response
                try:
                    error_data = response.json()
                    if 'errors' in error_data:
                        error_details = error_data['errors']
                        error_msg = str(error_details)
                    elif 'message' in error_data:
                        error_msg = error_data['message']
                except:
                    # If not JSON, use text response
                    if response.text:
                        error_msg = response.text.strip()
                
                # Provide helpful debugging info
                debug_info = (
                    f"URL: {url}\n"
                    f"Token ID: {self.token_id}\n"
                    f"Auth Header: PVEAPIToken={self.token_id}=<secret>\n"
                    f"Response: {error_msg}"
                )
                raise ConnectionError(f"Authentication failed (401): {debug_info}")
            
            # Check for other HTTP errors
            if response.status_code >= 400:
                error_msg = response.text or f"HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    if 'errors' in error_data:
                        error_msg = str(error_data['errors'])
                except:
                    pass
                raise Exception(f"HTTP error {response.status_code}: {error_msg}")
            
            # Parse JSON response
            try:
                json_data = response.json()
                # Proxmox API returns data in 'data' key
                if 'data' in json_data:
                    return json_data['data']
                # Some endpoints might return data directly
                return json_data
            except ValueError as e:
                raise Exception(f"Invalid JSON response: {response.text[:200]}")
                
        except ConnectionError:
            # Re-raise authentication errors as-is
            raise
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Request failed: {str(e)}")
    
    def get_all_vms(self):
        """
        Fetch all VMs from all nodes in the Proxmox cluster.
        
        Returns:
            list: List of dictionaries containing VM information
        """
        all_vms = []
        
        try:
            # Try to use /cluster/resources endpoint first (more efficient, includes tags)
            try:
                resources = self._make_request('GET', '/cluster/resources', {'type': 'vm'})
                
                # Build a map of VMID to tags from cluster resources
                tags_map = {}
                for resource in resources:
                    if resource.get('type') == 'qemu':
                        vmid = resource.get('vmid')
                        if vmid:
                            # Tags are stored as comma or semicolon-separated string
                            tags_str = resource.get('tags', '')
                            tags = []
                            if tags_str:
                                # Handle both comma and semicolon separators
                                # Split by semicolon first, then by comma, and flatten
                                tags = []
                                for part in tags_str.split(';'):
                                    if ',' in part:
                                        tags.extend([tag.strip() for tag in part.split(',') if tag.strip()])
                                    else:
                                        tag = part.strip()
                                        if tag:
                                            tags.append(tag)
                            tags_map[vmid] = tags
                
                # Now get detailed VM info from each node
                nodes = self._make_request('GET', '/nodes')
                
                for node in nodes:
                    node_name = node['node']
                    
                    try:
                        # Get all VMs (QEMU/KVM) on this node
                        vms = self._make_request('GET', f'/nodes/{node_name}/qemu')
                        
                        for vm in vms:
                            # Filter out templates - templates have template=1
                            if vm.get('template', 0) == 1:
                                continue
                            
                            vmid = vm.get('vmid')
                            # Get tags from the map we built earlier
                            tags = tags_map.get(vmid, [])
                            
                            vm_info = {
                                'vmid': vmid,
                                'name': vm.get('name', ''),
                                'status': vm.get('status', 'unknown'),
                                'node': node_name,
                                'cpu': vm.get('cpu', 0),
                                'mem': vm.get('mem', 0),
                                'maxmem': vm.get('maxmem', 0),
                                'disk': vm.get('disk', 0),
                                'maxdisk': vm.get('maxdisk', 0),
                                'uptime': vm.get('uptime', 0),
                                'tags': tags
                            }
                            all_vms.append(vm_info)
                    
                    except Exception as e:
                        # Log error but continue with other nodes
                        print(f"Error fetching VMs from node {node_name}: {str(e)}")
                        continue
                
                return all_vms
            
            except Exception as cluster_error:
                # Fallback to the original method if cluster/resources doesn't work
                print(f"Warning: Could not use /cluster/resources endpoint: {str(cluster_error)}")
                print("Falling back to node-by-node method...")
                
                # Get all nodes
                nodes = self._make_request('GET', '/nodes')
                
                for node in nodes:
                    node_name = node['node']
                    
                    try:
                        # Get all VMs (QEMU/KVM) on this node
                        vms = self._make_request('GET', f'/nodes/{node_name}/qemu')
                        
                        for vm in vms:
                            # Filter out templates - templates have template=1
                            if vm.get('template', 0) == 1:
                                continue
                            
                            vmid = vm.get('vmid')
                            
                            # Get VM config to fetch tags
                            tags = []
                            try:
                                vm_config = self._make_request('GET', f'/nodes/{node_name}/qemu/{vmid}/config')
                                # Tags are stored as comma or semicolon-separated string in the config
                                tags_str = vm_config.get('tags', '')
                                if tags_str:
                                    # Handle both comma and semicolon separators
                                    # Split by semicolon first, then by comma, and flatten
                                    tags = []
                                    for part in tags_str.split(';'):
                                        if ',' in part:
                                            tags.extend([tag.strip() for tag in part.split(',') if tag.strip()])
                                        else:
                                            tag = part.strip()
                                            if tag:
                                                tags.append(tag)
                            except Exception as e:
                                # If we can't get tags, continue without them
                                print(f"Warning: Could not fetch tags for VM {vmid} on node {node_name}: {str(e)}")
                            
                            vm_info = {
                                'vmid': vmid,
                                'name': vm.get('name', ''),
                                'status': vm.get('status', 'unknown'),
                                'node': node_name,
                                'cpu': vm.get('cpu', 0),
                                'mem': vm.get('mem', 0),
                                'maxmem': vm.get('maxmem', 0),
                                'disk': vm.get('disk', 0),
                                'maxdisk': vm.get('maxdisk', 0),
                                'uptime': vm.get('uptime', 0),
                                'tags': tags
                            }
                            all_vms.append(vm_info)
                    
                    except Exception as e:
                        # Log error but continue with other nodes
                        print(f"Error fetching VMs from node {node_name}: {str(e)}")
                        continue
                
                return all_vms
        
        except Exception as e:
            raise Exception(f"Error fetching VMs from Proxmox: {str(e)}")
    
    def get_vm_details(self, vmid):
        """
        Get detailed information about a specific VM.
        
        Args:
            vmid (int): Virtual Machine ID
            
        Returns:
            dict: Detailed VM information
        """
        try:
            # Search through all nodes to find the VM
            nodes = self._make_request('GET', '/nodes')
            
            for node in nodes:
                node_name = node['node']
                
                try:
                    # Try to get VM status from this node
                    vm_status = self._make_request('GET', f'/nodes/{node_name}/qemu/{vmid}/status/current')
                    
                    # Get VM configuration
                    vm_config = self._make_request('GET', f'/nodes/{node_name}/qemu/{vmid}/config')
                    
                    # Extract tags from config (tags are stored as comma or semicolon-separated string)
                    tags = []
                    tags_str = vm_config.get('tags', '')
                    if tags_str:
                        # Handle both comma and semicolon separators
                        # Split by semicolon first, then by comma, and flatten
                        for part in tags_str.split(';'):
                            if ',' in part:
                                tags.extend([tag.strip() for tag in part.split(',') if tag.strip()])
                            else:
                                tag = part.strip()
                                if tag:
                                    tags.append(tag)
                    
                    # Combine status and config information
                    vm_details = {
                        'vmid': vmid,
                        'name': vm_config.get('name', ''),
                        'status': vm_status.get('status', 'unknown'),
                        'node': node_name,
                        'cpu': vm_status.get('cpu', 0),
                        'mem': vm_status.get('mem', 0),
                        'maxmem': vm_status.get('maxmem', 0),
                        'disk': vm_status.get('disk', 0),
                        'maxdisk': vm_status.get('maxdisk', 0),
                        'uptime': vm_status.get('uptime', 0),
                        'netin': vm_status.get('netin', 0),
                        'netout': vm_status.get('netout', 0),
                        'diskread': vm_status.get('diskread', 0),
                        'diskwrite': vm_status.get('diskwrite', 0),
                        'cores': vm_config.get('cores', 1),
                        'sockets': vm_config.get('sockets', 1),
                        'memory': vm_config.get('memory', 0),
                        'tags': tags
                    }
                    
                    return vm_details
                
                except Exception:
                    # VM not on this node, continue searching
                    continue
            
            # VM not found
            raise ValueError(f"VM with ID {vmid} not found")
        
        except ValueError:
            raise
        except Exception as e:
            raise Exception(f"Error fetching VM details: {str(e)}")
    
    def get_nodes(self):
        """
        Get list of all nodes in the Proxmox cluster.
        
        Returns:
            list: List of node information
        """
        try:
            nodes = self._make_request('GET', '/nodes')
            return [{'node': node['node'], 'status': node.get('status', 'unknown')} for node in nodes]
        except Exception as e:
            raise Exception(f"Error fetching nodes: {str(e)}")
    
    def get_all_storage(self):
        """
        Fetch all storage from all nodes in the Proxmox cluster.
        
        Returns:
            dict: Dictionary containing list of storage resources
        """
        result = {
            'storages': []
        }
        
        try:
            # Get all nodes
            nodes = self._make_request('GET', '/nodes')
            
            for node in nodes:
                node_name = node['node']
                
                try:
                    # Get storage information from this node
                    storages = self._make_request('GET', f'/nodes/{node_name}/storage')
                    
                    for storage in storages:
                        # Extract storage information
                        storage_name = storage.get('storage', '')
                        storage_type = storage.get('type', 'unknown')
                        content = storage.get('content', '')
                        total = storage.get('total', 0)  # Total space in bytes
                        used = storage.get('used', 0)    # Used space in bytes
                        avail = storage.get('avail', 0)  # Available space in bytes
                        active = storage.get('active', 0)  # 1 if active, 0 if not
                        enabled = storage.get('enabled', 1)  # 1 if enabled, 0 if not
                        
                        # Create storage info dictionary
                        storage_info = {
                            'id': f"{node_name}/{storage_name}",
                            'name': storage_name,
                            'node': node_name,
                            'type': 'proxmox',
                            'resource_type': 'proxmox_storage',
                            'storage_type': storage_type,  # dir, lvm, lvm-thin, zfspool, nfs, cifs, etc.
                            'content': content,  # images, iso, vztmpl, etc.
                            'total_bytes': total,
                            'used_bytes': used,
                            'avail_bytes': avail,
                            'active': active == 1,
                            'enabled': enabled == 1
                        }
                        
                        # Only add if not already in the list (storage can be shared across nodes)
                        # Check if this storage already exists
                        existing = next((s for s in result['storages'] if s['name'] == storage_name and s['node'] == node_name), None)
                        if not existing:
                            result['storages'].append(storage_info)
                
                except Exception as e:
                    # Log error but continue with other nodes
                    print(f"Error fetching storage from node {node_name}: {str(e)}")
                    continue
            
            return result
        
        except Exception as e:
            raise Exception(f"Error fetching storage from Proxmox: {str(e)}")
    
    def _find_vm_node(self, vmid):
        """
        Find which node a VM is running on.
        
        Args:
            vmid (int): Virtual Machine ID
            
        Returns:
            str: Node name where the VM is located
        """
        nodes = self._make_request('GET', '/nodes')
        for node in nodes:
            node_name = node['node']
            try:
                vms = self._make_request('GET', f'/nodes/{node_name}/qemu')
                for vm in vms:
                    if vm.get('vmid') == vmid:
                        return node_name
            except:
                continue
        raise ValueError(f"VM with ID {vmid} not found")
    
    def start_vm(self, vmid):
        """
        Start a virtual machine.
        
        Args:
            vmid (int): Virtual Machine ID
            
        Returns:
            dict: Task information
        """
        try:
            node_name = self._find_vm_node(vmid)
            # POST to start the VM
            result = self._make_request('POST', f'/nodes/{node_name}/qemu/{vmid}/status/start')
            return result
        except ValueError:
            raise
        except Exception as e:
            raise Exception(f"Error starting VM {vmid}: {str(e)}")
    
    def shutdown_vm(self, vmid):
        """
        Shutdown a virtual machine gracefully.
        
        Args:
            vmid (int): Virtual Machine ID
            
        Returns:
            dict: Task information
        """
        try:
            node_name = self._find_vm_node(vmid)
            # POST to shutdown the VM gracefully
            result = self._make_request('POST', f'/nodes/{node_name}/qemu/{vmid}/status/shutdown')
            return result
        except ValueError:
            raise
        except Exception as e:
            raise Exception(f"Error shutting down VM {vmid}: {str(e)}")
    
# VNC console functionality has been removed

# Global instance (lazy initialization)
_proxmox_client = None

def get_proxmox_client():
    """Get or create the global Proxmox client instance"""
    global _proxmox_client
    if _proxmox_client is None:
        _proxmox_client = ProxmoxClient()
    return _proxmox_client
