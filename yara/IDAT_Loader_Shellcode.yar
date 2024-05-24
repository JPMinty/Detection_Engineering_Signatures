rule IDAT_Loader_Encrypted_Payload
{
    meta:
        description = "Detects known XOR key offset bytes in IDAT streams used by IDAT / Hijack Loader"
        author = "Jai Minton (@CyberRaiju) - Huntress"
        source = "https://www.rapid7.com/blog/post/2023/08/31/fake-update-utilizes-new-idat-loader-to-execute-stealc-and-lumma-infostealers/"
        hash = "b3d8bc93a96c992099d768beb42202b48a7fe4c9a1e3b391efbeeb1549ef5039"
        decryption_tool = "https://github.com/rapid7/Rapid7-Labs/blob/main/Malware%20Config%20Extractors/IDAT_Loader_extractor.py"
        date = "2024-05-24"
    strings:
        $idat_key = {49 44 41 54 C6 A5 79 EA}
    condition:
        filesize < 2MB and all of them
}