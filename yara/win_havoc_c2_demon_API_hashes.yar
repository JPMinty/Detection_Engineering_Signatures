/*
   Author: @CyberRaiju
   Date: 2024-03-18
   Identifier: b25f7139-0870-4c0c-94ef-3bdb304997bd
   Sample: https://www.unpac.me/results/4e15055e-fce8-4115-835e-bdc816a54749#/
*/

rule win_havoc_c2_demon_API_hashes {
	meta:
		description = "Detects API hashes used in Havoc C2 to resolve Windows APIs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Jai Minton (@CyberRaiju) - https://www.jaiminton.com/"
		reference = "https://www.youtube.com/@cyberraiju/playlists"
		date = "2024-03-18"
		hash1 = "0bc017b4114310f023c4b965271b4d089b467dfd55c2cd32d0814afc08ff488a"
		hash2 = "b953ef3b1dd6e08d2179ae23624e0051c15754656d97fb8ca2461416360b05bf"
		hash3 = "068c44d322748e817b3609e263c9b276d5b12e8ff5e8ad66b296e21d5646011e"
		hash4 = "35ef0c05bc16af0420825f12b812ca0df56172b3807480d39a2042f090174cb3"
		hash5 = "a78a8dd4f4f4a99387e2f26b2b20d10d0647a3cfde19619bb250650998abd7f3"
		hash6 = "f81af020d914b0c32c5a5e70735d1a3498be73328f82d77d63f2a20c05809017"
	strings:
		$ntdll_hash = {53 17 e6 70} //Ntdll
		$API_LdrGetProcedureAddress = {b6 6b e7 fc} //LdrGetProcedureAddress
		$API_LdrLoadDll = {43 6a 45 9e} //LdrLoadDll
		$API_RtlAllocateHeap = {5a 4c e9 3b} //RtlAllocateHeap
		$API_RtlReAllocateHeap = {71 03 74 af} //RtlReAllocateHeap
		$API_RtlFreeHeap = {d7 e4 a9 73} //RtlFreeHeap
		$API_RtlExitUserThread = {e8 b5 6d 2f} //RtlExitUserThread
		$API_RtlExitUserProcess = {2f c7 57 00} //RtlExitUserProcess
		$API_RtlRandomEx = {f5 24 12 7f} //RtlRandomEx
		$API_RtlNtStatusToDosError = {90 c8 d7 39} //RtlNtStatusToDosError
		$API_RtlGetVersion = {dd 5c de 0d} //RtlGetVersion
		$API_RtlCreateTimerQueue = {31 3c ef 50} //RtlCreateTimerQueue
		$API_RtlCreateTimer = {ec fa 77 18} //RtlCreateTimer
		$API_RtlQueueWorkItem = {8e 02 92 ae} //RtlQueueWorkItem
		$API_RtlRegisterWait = {91 e6 0f 60} //RtlRegisterWait
		$API_RtlDeleteTimerQueue = {b0 88 c1 ee} //RtlDeleteTimerQueue
		$API_RtlCaptureContext = {10 d9 a8 eb} //RtlCaptureContext
		$API_RtlAddVectoredExceptionHandler = {89 6c f0 2d} //RtlAddVectoredExceptionHandler
		$API_RtlRemoveVectoredExceptionHandler = {8e 01 1b ad} //RtlRemoveVectoredExceptionHandler
		$API_RtlCopyMappedMemory = {02 b3 56 5b} //RtlCopyMappedMemory
		$API_NtClose = {9d e6 d6 40} //NtClose
		$API_NtCreateEvent = {3d 23 d3 28} //NtCreateEvent
		$API_NtSetEvent = {b5 d8 87 cb} //NtSetEvent
		$API_NtSetInformationThread = {f1 03 3c 0c} //NtSetInformationThread
		$API_NtSetInformationVirtualMemory = {39 c2 6a 94} //NtSetInformationVirtualMemory
		$API_NtGetNextThread = {9e fb 10 a4} //NtGetNextThread
		$API_NtOpenProcess = {18 f7 82 4b} //NtOpenProcess
		$API_NtTerminateProcess = {4f dd d9 4e} //NtTerminateProcess
		$API_NtQueryInformationProcess = {c2 5d dc 8c} //NtQueryInformationProcess
		$API_NtQuerySystemInformation = {28 39 c2 7b} //NtQuerySystemInformation
		$API_NtAllocateVirtualMemory = {ec b8 83 f7} //NtAllocateVirtualMemory
		$API_NtQueueApcThread = {b8 64 66 0a} //NtQueueApcThread
		$API_NtOpenThread = {b1 0c 8e 96} //NtOpenThread
		$API_NtOpenThreadToken = {d2 47 33 80} //NtOpenThreadToken
		$API_NtResumeThread = {d0 c3 4b 5a} //NtResumeThread
		$API_NtSuspendThread = {e1 93 3d e4} //NtSuspendThread
		$API_NtDuplicateObject = {59 d8 41 44} //NtDuplicateObject
		$API_NtGetContextThread = {84 f8 22 6d} //NtGetContextThread
		$API_NtSetContextThread = {10 bf a0 ff} //NtSetContextThread
		$API_NtWaitForSingleObject = {3c 0c ac e8} //NtWaitForSingleObject
		$API_NtAlertResumeThread = {28 1e a1 5b} //NtAlertResumeThread
		$API_NtSignalAndWaitForSingleObject = {ed 3a 98 78} //NtSignalAndWaitForSingleObject
		$API_NtTestAlert = {df 32 8a 85} //NtTestAlert
		$API_NtCreateThreadEx = {b0 cf 18 af} //NtCreateThreadEx
		$API_NtOpenProcessToken = {99 ca 0d 35} //NtOpenProcessToken
		$API_NtDuplicateToken = {23 0b 16 8e} //NtDuplicateToken
		$API_NtProtectVirtualMemory = {88 28 e9 50} //NtProtectVirtualMemory
		$API_NtTerminateThread = {08 88 f5 cc} //NtTerminateThread
		$API_NtWriteVirtualMemory = {92 01 17 c3} //NtWriteVirtualMemory
		$API_NtContinue = {2c 6c 3a fc} //NtContinue
		$API_NtReadVirtualMemory = {03 81 28 a3} //NtReadVirtualMemory
		$API_NtFreeVirtualMemory = {09 c6 02 28} //NtFreeVirtualMemory
		$API_NtUnmapViewOfSection = {cd 12 a4 6a} //NtUnmapViewOfSection
		$API_NtQueryVirtualMemory = {5d e8 c0 10} //NtQueryVirtualMemory
		$API_NtQueryInformationToken = {e4 1f 37 0f} //NtQueryInformationToken
		$API_NtQueryInformationThread = {1b 46 a0 f5} //NtQueryInformationThread
		$API_NtQueryObject = {b4 c9 5d c8} //NtQueryObject
		$API_NtTraceEvent = {d8 5c c2 70} //NtTraceEvent
	condition:
		filesize < 1000KB and (uint16(0) == 0x5a4d) and (2 of them)
}