rule Redline {
    meta:
        author = "Joe Khawand"
        description = "Detects RedLine infostealer from unpacked 5ffecf27b187bcaec80b45b570631e5bd53672b23dedb4d28d4e3dc6e81214b1 file"
        hash="5ffecf27b187bcaec80b45b570631e5bd53672b23dedb4d28d4e3dc6e81214b1"

    strings:
        $s_1 = "DownloadAndExecuteUpdate" fullword ascii
        $s_2 = "ITaskProcessor" fullword ascii
        $s_3 = "CommandLineUpdate" fullword ascii
        $s_4 = "DownloadUpdate" fullword ascii
        $s_5 = "FileScanning" fullword ascii
        $s_6 = "GetLenToPosState" fullword ascii
        $s_7 = "RecordHeaderField" fullword ascii
        $s_8 = "EndpointConnection" fullword ascii
        $s_9 = "BCRYPT_KEY_LENGTHS_STRUCT" fullword ascii
    condition:
        6 of ($s_*)