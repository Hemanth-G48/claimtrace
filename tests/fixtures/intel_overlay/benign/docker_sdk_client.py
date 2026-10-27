import docker


def local_client():
    """Connect to the local daemon socket (/var/run/docker.sock) via the SDK."""
    return docker.from_env()
