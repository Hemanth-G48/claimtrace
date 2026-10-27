import subprocess

subprocess.run(
    [
        "curl",
        "--unix-socket",
        "/var/run/docker.sock",
        "-X",
        "POST",
        "http://localhost/containers/create",
    ],
    check=False,
)
