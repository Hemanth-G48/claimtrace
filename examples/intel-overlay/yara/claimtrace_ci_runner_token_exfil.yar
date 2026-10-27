rule claimtrace_ci_runner_token_exfil
{
    meta:
        description = "Reads a CI runner/OIDC token and combines it with a network call"
        severity = "high"
        confidence = "medium"
        author = "claimtrace"
        reference = "https://attack.mitre.org/techniques/T1552/001/"

    strings:
        $tok1 = "ACTIONS_RUNTIME_TOKEN" ascii
        $tok2 = "ACTIONS_ID_TOKEN_REQUEST_TOKEN" ascii
        $tok3 = "GITLAB_CI_JOB_TOKEN" ascii
        $net1 = "requests.post" ascii
        $net2 = "httpx.post" ascii
        $net3 = "urlopen" ascii
        $net4 = "fetch(" ascii
        $net5 = "curl " ascii

    condition:
        any of ($tok*) and any of ($net*)
}
