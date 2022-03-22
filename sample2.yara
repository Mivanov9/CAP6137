import "pe"

rule sample2 {
    meta:
        author = "Michael Ivanov"
    strings:
        $s1 = "Wow64DisableWow64FsRedirection" fullword ascii
        $s2 = "NtQueryInformationProcess" fullword ascii
        $s3 = "GetProcAddress" fullword ascii
        $s4 = "IDR_X86BOT" fullword ascii
    condition:
        uint16(0) == 0x5A4D
        and $s1 and $s2 and $s3 and $s4
}
