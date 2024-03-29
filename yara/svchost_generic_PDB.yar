rule svchost_generic_PDB  {
   meta:
      description = "Detects svchost PDB string in file"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Jai Minton - @CyberRaiju"
      reference = "https://blog.reversinglabs.com/blog/taidoor-a-truly-persistent-threat"
	  reference = "https://twitter.com/CyberRaiju/status/1579732822063218691"
      date = "2022-10-11"
   strings:
      $s1 = /\\Debug\\.{,20}svchost.{,10}.pdb/
      $s2 = /\\Release\\.{,20}svchost.{,10}.cpp/
      $s3 = /\\Debug\\.{,20}svchost.{,10}.pdb/
      $s4 = /\\Release\\.{,20}svchost.{,10}.cpp/
   condition:
      uint16(0) == 0x5a4d and filesize < 1001KB and 1 of them
}
