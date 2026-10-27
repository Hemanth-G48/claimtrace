rule claimtrace_paste_site_exfil
{
    meta:
        description = "Uploads local file or environment data to a paste/transfer service"
        severity = "high"
        confidence = "medium"
        author = "claimtrace"
        reference = "https://attack.mitre.org/techniques/T1567/002/"

    strings:
        $svc1 = "pastebin.com/api" ascii nocase
        $svc2 = "transfer.sh" ascii nocase
        $svc3 = "0x0.st" ascii nocase
        $svc4 = "file.io" ascii nocase
        $svc5 = "paste.ee" ascii nocase
        $src1 = "os.environ" ascii
        $src2 = "process.env" ascii
        $src3 = "read_text" ascii
        $src4 = "read_bytes" ascii
        $src5 = "open(" ascii
        $src6 = "base64" ascii

    condition:
        any of ($svc*) and any of ($src*)
}
