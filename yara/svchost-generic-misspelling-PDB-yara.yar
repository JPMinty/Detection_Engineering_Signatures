rule svchost_generic_misspelling_PDB  {
   meta:
      description = "Detects svchost misspelling PDB string in file"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Jai Minton - @CyberRaiju"
      date = "2022-10-11"
   strings:
      $s1 = /\\Debug\\.{,20}svch0st.{,10}.pdb/
      $s2 = /\\Release\\.{,20}svch0st.{,10}.cpp/
      $s3 = /\\Debug\\.{,20}svch0st.{,10}.pdb/
      $s4 = /\\Release\\.{,20}svch0st.{,10}.cpp/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}