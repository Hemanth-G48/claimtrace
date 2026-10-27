rule claimtrace_docker_socket_control
{
    meta:
        description = "Reaches the Docker daemon socket to create or exec containers"
        severity = "high"
        confidence = "medium"
        author = "claimtrace"
        reference = "https://attack.mitre.org/techniques/T1611/"

    strings:
        $sock1 = "/var/run/docker.sock" ascii
        $sock2 = "unix:///var/run/docker.sock" ascii
        $ctl1 = "/containers/create" ascii
        $ctl2 = "--unix-socket" ascii
        $ctl3 = "docker exec" ascii

    condition:
        any of ($sock*) and any of ($ctl*)
}
