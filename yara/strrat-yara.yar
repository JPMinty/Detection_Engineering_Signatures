/*
   Author: @CyberRaiju
   Date: 2022-05-19
   Identifier: STRRAT-Identification
   Reference: https://www.jaiminton.com/reverse-engineering/strrat
*/

rule STRRAT_14 {
   meta:
	  description = "Detects components or the presence of STRRat used in eCrime operations"
	  license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
	  author = "Jai Minton (@CyberRaiju)"
	  reference = "https://www.jaiminton.com/reverse-engineering/strrat"
	  date = "2022-05-19"
	  hash1 = "ec48d708eb393d94b995eb7d0194bded701c456c666c7bb967ced016d9f1eff5"
	  hash2 = "0A6D2526077276F4D0141E9B4D94F373CC1AE9D6437A02887BE96A16E2D864CF"
   strings:
	  $ntwk1 = "wshsoft.company" fullword ascii
	  $ntwk2 = "str-master.pw" fullword ascii
	  $ntwk3 = "jbfrost.live" fullword ascii
	  $ntwk4 = "ip-api.com" fullword ascii
	  $ntwk5 = "strigoi" fullword ascii
	  $host1 = "ntfsmgr" fullword ascii
	  $host2 = "Skype" fullword ascii
	  $host3 = "lock.file" fullword ascii
	  $rat1 = "HBrowserNativeApis" fullword ascii
	  $rat2 = "carLambo" fullword ascii
	  $rat3 = "config" fullword ascii
	  $rat4 = "loorqhustq" fullword ascii
	  
   condition:
	  filesize < 2000KB and (2 of ($ntwk*) or (1 of ($host*) and 2 of ($rat*)))
}
