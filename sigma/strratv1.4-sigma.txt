title: STTRAT Child Process Spawning
description: Detects suspicious child processes of Java(w) possibly associated with a STRRAT infection.
status: experimental
author: Jai Minton (@CyberRaiju)
references: https://www.jaiminton.com/reverse-engineering/strrat
date: 2022/05/28
modified: 2022/05/28
tags:
  - attack.initial_access
  - attack.persistence
logsource:
  category: process_creation
  product: windows
level: high
detection:
  selection:
	ParentImage|endswith:
	  - '\java.exe'
	  - '\javaw.exe'
	Image|endswith:
	  - '\cmd.exe'
	  - '\hrdpinst.exe'
	CommandLine|contains:
	  - 'schtasks /create /sc minute /mo 30 /tn Skype'
	  - 'reg add'
	  - 'shutdown /r /t 0'
	  - 'shutdown /s /t 0'
	  - 'wmic /node:. /namespace:'
	  - 'hrdpinst.exe'
	  - 'notepad'
  condition: selection
falsepositives:
  - Legitimate calls of various java applications to system binaries with specific command lines