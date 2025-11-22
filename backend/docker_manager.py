import docker
import random
import string
import logging
from config import settings

logger = logging.getLogger(__name__)

class DockerManager:
    def __init__(self):
        try:
            self.client = docker.DockerClient(base_url=settings.DOCKER_SOCKET_PATH)
        except Exception as e:
            logger.error(f"Failed to connect to Docker: {e}")
            self.client = None

    def get_available_port(self, start=6901, end=7000):
        # In a real app, we'd check which ports are actually in use.
        # For simplicity, we'll pick a random one and hope for the best, 
        # or better, let Docker map it and we find out which one it mapped.
        # However, KasmVNC images usually expose 6901. 
        # We will let Docker map 6901 to a random host port to avoid conflicts.
        return None # Logic handled in start_container

    def start_container(self, image_name: str, user_name: str):
        if not self.client:
            raise Exception("Docker client not initialized")

        # Generate a unique container name
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        container_name = f"vnc_{user_name}_{suffix}"
        
        try:
            # Pull image if it doesn't exist
            try:
                self.client.images.get(image_name)
                logger.info(f"Image {image_name} already exists")
            except docker.errors.ImageNotFound:
                logger.info(f"Pulling image {image_name}...")
                self.client.images.pull(image_name)
                logger.info(f"Image {image_name} pulled successfully")
            
            # KasmVNC images expose 6901 for HTTPS VNC
            # We map 6901 to a random port on the host
            container = self.client.containers.run(
                image=image_name,
                name=container_name,
                detach=True,
                ports={'6901/tcp': None}, # Bind to random available port
                environment={
                    'VNC_PW': 'password', # Default password, can be randomized
                    'VNC_USER': 'kasm_user'
                },
                shm_size='512m' # Recommended for VNC
            )
            
            # Reload to get the mapped ports
            container.reload()
            ports = container.attrs['NetworkSettings']['Ports']
            host_port = ports['6901/tcp'][0]['HostPort']
            
            return {
                "container_id": container.id,
                "container_name": container_name,
                "vnc_port": int(host_port),
                "vnc_password": "password", # Hardcoded for now, but passed explicitly
                "status": "running"
            }
        except Exception as e:
            logger.error(f"Failed to start container: {e}")
            raise e

    def stop_container(self, container_id: str):
        if not self.client:
            return
        try:
            container = self.client.containers.get(container_id)
            container.stop()
            container.remove()
        except docker.errors.NotFound:
            pass # Already gone
        except Exception as e:
            logger.error(f"Failed to stop container {container_id}: {e}")
            raise e

    def get_container_status(self, container_id: str):
        if not self.client:
            return "unknown"
        try:
            container = self.client.containers.get(container_id)
            return container.status
        except docker.errors.NotFound:
            return "stopped"
        except Exception as e:
            logger.error(f"Error getting status for {container_id}: {e}")
            return "error"

docker_manager = DockerManager()
