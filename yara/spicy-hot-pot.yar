/*

   YARA Rule Set
   Author: jai-minton
   Date: 2020-11-01
   Identifier: SpicyHotPot
   Reference: https://www.crowdstrike.com/blog/author/jai-minton/
   copyright = “(c) 2020 CrowdStrike Inc.”

*/

/* Rule Set —————————————————————– */

rule SpicyHotPot_wdlogin {
   meta:
      description = "SpicyHotPot - wdlogin.exe: Used to identify memory dump uploading component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "7c0fdee3670cc53a22844d691307570a21ae3be3ce4b66e46bb6d9baad1774b8"
   strings:
      $x1 = "D:\\Work\\Install_Driver\\Driver_helper\\Release\\wdlogin.pdb" fullword ascii
      $x2 = "kmdf_protect.sys" fullword ascii
      $x3 = "kmdf_look.sys" fullword ascii
      $x4 = "/api/v1/post_dump" fullword ascii
      $s1 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii
      $s2 = "https://db.testyk.com" fullword ascii
      $s3 = "https://da.testiu.com" fullword ascii
      $s4 = "https://du.testjj.com" fullword ascii
      $s5 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii
      $s6 = "No more connections allowed to host %s: %zu" fullword ascii
      $s7 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii
      $s8 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii
      $s9 = "dumping" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of ($x*) and 3 of ($s*)
}

rule SpicyHotPot__J861 {
   meta:
      description = "SpicyHotPot - _J861.exe: Used to identify system fingerprinting, enumeration and networking component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "c83e6b96ee3aa1a580157547eae88d112d2202d710218f2ed496f7fe3d861abc"
   strings:
      $x1 = "E:\\work\\Icon_Report\\Release\\_service.pdb" fullword ascii
      $x2 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii
      $x3 = "https://du.testjj.com/api/v1/id" fullword ascii
      $s1 = "SEC_E_ILLEGAL_MESSAGE (0x%08X)" ascii
      $s2 = "Failed reading the chunked-encoded stream" fullword ascii
      $s3 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii
      $s4 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s5 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii
      $s6 = "failed to load WS2_32.DLL (%u)" fullword ascii
      $s7 = "/c ping -n 3 127.1 >nul & del /q %s" fullword ascii
      $s8 = "No more connections allowed to host %s: %zu" fullword ascii
      $s9 = "%d ReadPhysicalDriveInNTUsingSmart ERROR DeviceIoControl(%d, SMART_GET_VERSION) returned 0, error is %d" fullword ascii
      $s10 = "%d ReadPhysicalDriveInNTWithAdminRights ERROR DeviceIoControl() %d, DFP_GET_VERSION) returned 0, error is %d" fullword ascii
      $s11 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii
      $s12 = "Content-Type: %s%s%s" fullword ascii
      $s13 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii
      $s14 = "No valid port number in connect to host string (%s)" fullword ascii
      $s15 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 2 of ($x*) and 8 of ($s*)
}

rule SpicyHotPot_wuhost {
   meta:
      description = "SpicyHotPot - wuhost.exe: Used to identify rootkit and module updating component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "eb54cd2d61507b9e98712de99834437224b1cef31a81544a47d93e470b8613fc"
   strings:
      $x1 = "wdlogin.exe" fullword ascii
      $x2 = "UpdateTemp.exe" fullword ascii
      $x3 = "UpdateSelf.exe" fullword ascii
      $x4 = "wrme.exe" fullword ascii
      $x5 = "wccenter.exe" fullword ascii
      $x6 = "D:\\Work\\Install_Driver\\Driver_helper\\Release\\wuhost.pdb" fullword ascii
      $x7 = "wuhost.exe" fullword ascii
      $s1 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii
      $s2 = "Failed reading the chunked-encoded stream" fullword ascii
      $s3 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii
      $s4 = "https://db.testyk.com" fullword ascii
      $s5 = "https://da.testiu.com" fullword ascii
      $s6 = "https://du.testjj.com" fullword ascii
      $s7 = "dump_temp" fullword ascii
      $s8 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s9 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii
      $s10 = "failed to load WS2_32.DLL (%u)" fullword ascii
      $s11 = "No more connections allowed to host %s: %zu" fullword ascii
      $s12 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 2 of ($x*) and 4 of them
}

rule SpicyHotPot_wrme {
   meta:
      description = "SpicyHotPot - wrme.exe: Used to identify module starting and reporting component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "7e489f1f72cac9f1c88bdc6be554c78b5a14197d63d1bae7e41de638e903af21"
   strings:
      $x1 = "DvUpdate.exe" fullword ascii
      $x2 = "D:\\Work\\Install_Driver\\Driver_helper\\Release\\wrme.pdb" fullword ascii
      $x3 = "No more connections allowed to host %s: %zu" fullword ascii
      $s1 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii
      $s2 = "Failed reading the chunked-encoded stream" fullword ascii
      $s3 = "Content-Type: %s%s%s" fullword ascii
      $s4 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii
      $s5 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii
      $s6 = "https://db.testyk.com" fullword ascii
      $s7 = "https://da.testiu.com" fullword ascii
      $s8 = "https://du.testjj.com" fullword ascii
      $s9 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s10 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii
      $s11 = "failed to load WS2_32.DLL (%u)" fullword ascii
      $s12 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii
      $s13 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 2 of ($x*) and 7 of ($s*)
}

rule SpicyHotPot_DvLayout {
   meta:
      description = "SpicyHotPot - DvLayout.exe: Used to identify rootkit installation component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "551c4564d5ff537572fd356fe96df7c45bf62de9351fae5bb4e6f81dcbe34ae5"
   strings:
      $x1 = "KMDF_LOOK.sys" fullword ascii
      $x2 = "KMDF_Protect.sys" fullword ascii
      $x3 = "StartService Error, errorode is : %d ." fullword ascii
      $x4 = "Software\\Microsoft\\%s\\st" fullword wide
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "@api-ms-win-core-synch-l1-2-0.dll" fullword wide
      $s3 = "Genealogy.ini" fullword wide
      $s4 = "powercfg /h off" fullword ascii
      $s5 = " Type Descriptor'" fullword ascii
      $s6 = "find %s failed , errorcode : %d" fullword ascii
      $s7 = "find %s failed , errorcode : %d" fullword ascii
      $s8 = "Delete %s failed , errorcode : %d" fullword wide
      $s9 = "Delete %s failed , errorcode : %d" fullword wide
      $s10 = "OpenService failed , errorcode : %d" fullword wide
      $s11 = "&Beijing JoinHope Image Technology Ltd.1/0-" fullword ascii
      $s12 = "/c del /q %s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and 1 of ($x*) and 5 of ($s*)
}

rule SpicyHotPot_wccenter {
   meta:
      description = "SpicyHotPot - wccenter.exe: Used to identify malware that communicates with the rootkit component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "17095beda4afeabb7f41ff07cf866ddc42e49da1a4ed64b9c279072caab354f6"
   strings:
      $x1 = "D:\\Work\\Install_Driver\\Driver_helper\\Release\\wccenter.pdb" fullword ascii
      $x2 = "wdlogin.exe" fullword wide
      $x3 = "wuhost.exe" fullword wide
      $x4 = "wrme.exe" fullword wide
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = "&Beijing JoinHope Image Technology Ltd.1/0-" fullword ascii
      $s4 = "operator co_await" fullword ascii
      $s5 = "&Beijing JoinHope Image Technology Ltd.0" fullword ascii
      $s6 = "RvVersion" fullword wide
      $s7 = " Class Hierarchy Descriptor'" fullword ascii
      $s8 = "Base Class Descriptor" ascii
      $s9 = "Beijing1" fullword ascii
      $s10 = " Complete Object Locator'" fullword ascii
condition:
   uint16(0) == 0x5a4d and filesize < 400KB and 2 of ($x*) and 4 of ($s*)
}

rule SpicyHotPot_KMDF_LOOK {
   meta:
      description = "SpicyHotPot - KMDF_LOOK.sys: Used to identify browser hijacking component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "39764e887fd0b461d86c1be96018a4c2a670b1de90d05f86ed0acb357a683318"
   strings:
      $x1 = "G:\\SVN\\" ascii
      $s1 = "TSWebDownLoadProtect.dll" fullword wide
      $s2 = "ShellIco.dll" fullword wide
      $s3 = "QMLogEx.dll" fullword wide
      $s4 = "SSOCommon.dll" fullword wide
      $s5 = "TsService.exe" fullword ascii
      $s6 = "Hookport.sys" fullword wide
      $s7 = "SafeWrapper32.dll" fullword wide
      $s8 = "safemon.dll" fullword wide
      $s9 = "iNetSafe.dll" fullword wide
      $s10 = "ieplus.dll" fullword wide
      $s11 = "wdui2.dll" fullword wide
      $s12 = "ExtBhoIEToSe.dll" fullword wide
      $s13 = "360NetBase.dll" fullword wide
      $s14 = "urlproc.dll" fullword wide
      $s15 = "360sdbho.dll" fullword wide
      $s16 = "360base.dll" fullword wide
      $s17 = "360UDiskGuard.dll" fullword wide
      $s18 = "TSClinicWebFix.dll" fullword wide
      $s19 = "QMEmKit.dll" fullword wide
      $s20 = "WdHPFileSafe.dll" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 8 of them
}

rule SpicyHotPot_KMDF_Protect {
   meta:
      description = "SpicyHotPot - KMDF_Protect.sys: Used to identify driver protection and filtering component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "ab0418eb1863c8a2211d06c764f45884c9b7dbd6d1943137fc010b8f3b8d14ae"
   strings:
      $x1 = "wdlogin.exe" fullword wide
      $x2 = "\\Windows\\System32\\cmd.exe" fullword wide
      $x3 = "wuhost.exe" fullword wide
      $x4 = "wrme.exe" fullword wide
      $x5 = "UpdateSelf.exe" fullword ascii
      $x6 = "wccenter.exe" fullword wide
      $s1 = "jCloudScan.dll" fullword wide
      $s2 = "DSFScan.dll" fullword wide
      $s3 = "avescan.dll" fullword wide
      $s4 = "\\Cloudcom2.dll" fullword wide
      $s5 = "\\Cloudcom264.dll" fullword wide
      $s6 = "AVEIEngine.dll" fullword wide
      $s7 = "AVEI.dll" fullword wide
      $s8 = "BAPI.dll" fullword wide
      $s9 = "BAPI64.dll" fullword wide
      $s10 = "360Tray.exe" fullword ascii
      $s11 = "360Safe.exe" fullword ascii
      $s12 = "\\jCloudScan.dll" fullword wide
      $s13 = "\\deepscan64.dll" fullword wide
      $s14 = "\\deepscan.dll" fullword wide
condition:
   uint16(0) == 0x5a4d and filesize < 1000KB and 2 of ($x*) and 6 of ($s*)
}