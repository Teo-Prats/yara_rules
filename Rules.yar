rule Detect_IsDebuggerPresent : AntiDebug {
    meta:
        author = "naxonez"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    strings:
        $1 ="IsDebuggerPresent" 
    condition:
         any of them
}

rule NtQueryInformationProcess: AntiDebug {
    meta: 
        description = "Detect NtQueryInformationProcess as anti-debug"
        author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    strings:
        $1 = "NtQueryInformationProcess" 
    condition:   
       any of them
}

rule NtSetInformationThread: AntiDebug {
    meta: 
        description = "Detect NtSetInformationThread as anti-debug"
        author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
        reference = "https://unprotect.it/technique/ntsetinformationthread/"
    strings:
        $1 = "NtSetInformationThread" 
    condition:   
       any of them
}

rule NtQueryObject: AntiDebug {
    meta: 
        description = "Detect NtQueryObject as anti-debug"
        author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
        reference = "https://unprotect.it/technique/ntqueryobject/"
    strings:
        $1 = "NtQueryObject" wide ascii
    condition:   
       any of them
}

import "pe"
rule OutputDebugString: AntiDebug{
	meta:
		Author = "Teo-Prats"
		Description = "Detect OutputDebugstring"
		Reference = "http://twitter.com/j0sm1"
	condition:	
		pe.imports("kernel32.dll","OutputDebugStringA")
}

rule EventPairHandles: AntiDebug {
    meta: 
        description = "Detect EventPairHandlesas anti-debug"
        author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
        Reference = "https://unprotect.it/technique/eventpairhandles/"
    strings:
        $1 = "EventPairHandles"  
        $2 = "RtlCreateQueryDebugBuffer"  
        $3 = "RtlQueryProcessHeapInformation"  
    condition:   
        1 of them 
}

rule CsrGetProcessID: AntiDebug {
    meta: 
        description = "Detect CsrGetProcessID as anti-debug"
        author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
         Reference = "https://unprotect.it/technique/csrgetprocessid/"
    strings:
        $1 = "CsrGetProcessID" fullword
        $2 = "GetModuleHandle" fullword
    condition:   
        1 of them 
}

rule CloseHandle: AntiDebug {
    meta: 
        description = "Detect CloseHandle as anti-debug"
        author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
        Reference = "https://unprotect.it/technique/closehandle-ntclose/"
    strings:
        $1 = "NtClose" fullword  
        $2 = "CloseHandle" fullword  
    condition:   
        any of them
}

rule DebuggerCheck__GlobalFlags  {
    meta:
	description = "Rule to detect NtGlobalFlags debugger check"
        author = "Thibault Seret"
        date = "2020-09-26"
        Reference = "https://unprotect.it/technique/ntglobalflag/"
    strings:
        $s1 = "NtGlobalFlags" 
    condition:
        any of them
}

rule RDTSC: AntiDebug {
    meta: 
        description = "Detect RDTSC as anti-debug"
        author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
        reference = "https://unprotect.it/technique/rdtsc/"
    strings:
        $1 = { 0F 31 }
    condition:   
        $1
}

import "pe"
rule Detect_FindWindowA_iat {
	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if FindWindowA() is imported"
		Date = "20/04/2015"
		Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#OllyFindWindow"
	strings:
		$ollydbg = "OLLYDBG"
		$windbg = "WinDbgFrameClass"
	condition:
		pe.imports("user32.dll","FindWindowA") and ($ollydbg or $windbg)
}

rule EnumProcess: AntiDebug {
    meta: 
        description = "Detect EnumProcessas anti-debug"
         author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
        reference = "https://unprotect.it/technique/detecting-running-process-enumprocess-api/"
    strings:
        $1 = "EnumProcessModulesEx" wide ascii fullword
        $2 = "EnumProcesses" wide ascii fullword
        $3 = "EnumProcessModules" wide ascii fullword
    condition:   
        any of them 
}

rule detect_tlscallback {
    meta:
        description = "Simple rule to detect tls callback as anti-debug."
        author = "Thomas Roccia | @fr0gger_"
    strings:
        $str1 = "TLS_CALLBACK" nocase 
        $str2 = "TLScallback" nocase 
    condition:
        any of them
}

rule OllyDBG_BadFormatTrick: AntiDebug {
    meta: 
        description = "Detect bad format not handled by Ollydbg"
        author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
        reference = "https://unprotect.it/technique/bad-string-format/"
     strings:
        $str1 = "%s%s.exe" fullword ascii
        $str2 = "%s%s%s" fullword ascii
        $str3 = "%s%s%s%s" fullword ascii
        $str4 = "%s%s%s%s%s" fullword ascii
    condition:   
        any of them
}

rule Detect_SuspendThread: AntiDebug {
    meta: 
        description = "Detect SuspendThread as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "UnhandledExcepFilter" fullword ascii
        $2 = "SetUnhandledExceptionFilter" fullword ascii
    condition:   
       any of them 
}

rule ExceptionBased_AntiDebugging {
    meta:
        description = "Detects the use of INT 3 or UD2 instructions for exception-based anti-debugging"
        author = "Teo-Prats"
        reference ="https://unprotect.it/technique/interrupts/"
    strings:
        $int3 = { CC }  
        $ud2 = { 0F 0B } 
    condition:
        $int3 or $ud2
}

rule Detect_Interrupt: AntiDebug {
    meta: 
        description = "Detect Interrupt instruction"
        author = "Unprotect"
        comment = "Experimental rule / the rule can be slow to use"
        reference ="https://anti-debug.checkpoint.com/techniques/process-memory.html#breakpoints | https://unprotect.it/technique/int3-instruction-scanning/"
    strings:
        $int3 = { CC }
        $intCD = { CD }
        $int03 = { 03 }
        $int2D = { 2D }
        $ICE = { F1 }
    condition:   
        any of them
}

rule Detect_SetDebugFilterState: AntiDebug {
    meta: 
        description = "Detect SetDebugFilterState as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtSetDebugFilterState" fullword ascii
        $2 = "DbgSetDebugFilterState" fullword ascii
    condition:   
       any of them 
}

rule GuardPages: AntiDebug {
    meta: 
        description = "Detect Guard Pages as anti-debug"
        author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
        Reference = "https://unprotect.it/technique/guard-pages/"
    strings:
        $1 = "GetSystemInfo" fullword ascii
        $2 = "VirtualAlloc" fullword ascii
        $3 = "RtlFillMemory" fullword ascii
        $4 ="VirtualProtect" fullword ascii
        $5 ="VirtualFree" fullword ascii
    condition:   
        4 of them 
}

rule SuspendThread: AntiDebug {
    meta: 
        description = "Detect SuspendThread as anti-debug"
        author = "Teo-Prats"
        comment = "Modified rule from UnProtect"
        Reference = "https://unprotect.it/technique/suspendthread/"        
    strings:
        $1 = "SuspendThread" fullword ascii
        $2 = "NtSuspendThread" fullword ascii
        $3 = "OpenThread" fullword ascii
        $4 ="SetThreadContext" fullword ascii
        $5 ="SetInformationThread" fullword ascii
        $x1 ="CreateToolHelp32Snapshot" fullword ascii
        $x2 ="EnumWindows" fullword ascii
    condition:   
        any of ($x1, $x2) and 2 of ($1, $2, $3, $4, $5)
}

rule Detect_LocalSize: AntiDebug {
    meta: 
        description = "Detect LocalSize as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "LocalSize" fullword ascii 
    condition:   
        $1
}

rule debugger_via_API {
    meta:
        name = "check for debugger via API"
        author = "Teo-Prats"
        comment = "Converted from CAPA to YARA rule"
        reference = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/CheckRemoteDebuggerPresent.cpp  |  michael.hunhoff@fireeye.com"
    strings:
        $api1 = "CheckRemoteDebuggerPresent"
        $api2 = "WudfIsAnyDebuggerPresent"
        $api3 = "WudfIsKernelDebuggerPresent"
        $api4 = "WudfIsUserDebuggerPresent"
    condition:
        any of ($api*)
}

rule PEB_BeingDebugged_flag {
    meta:
        name = "check for PEB BeingDebugged flag"
        author = "Teo-Prats"
        comment = "Converted from CAPA to YARA rule"
        references = "Practical Malware Analysis, Chapter 16, p. 353   | moritz.raabe@fireeye.com"
    strings:
        // Accessing PEB and checking BeingDebugged flag, typical instructions:
        $peb_access = { 64 A1 30 00 00 00 }  // MOV EAX, FS:[30h] (accessing PEB)
        $being_debugged_check = { 8B 40 02  // MOV EAX, [EAX+2h] (accessing BeingDebugged flag)
                                  84 C0     // TEST AL, AL (checking if flag is set)
                                  75 ?? }   // JNZ/JZ (conditional jump based on flag)
    condition:
        $peb_access and $being_debugged_check
}

rule GetTickCount {
    meta:
        name = "check for time delay via GetTickCount"
        author = "Teo-Prats"
        comment = "Converted from CAPA to YARA rule"
        references = "Practical Malware Analysis, Chapter 16, p. 353   | michael.hunhoff@fireeye.com" 
    strings:
        $GetTickCount = { FF 15 ?? ?? ?? ?? }  // Call to GetTickCount
        $GetTickCountString = "GetTickCount" fullword ascii
    condition:
        $GetTickCountString and #GetTickCount >= 2
}

rule CheckForHardwareBreakpoints {
    meta:
        name = "check for hardware breakpoints"
        author = "Teo-Prats"
        comment = "Converted from CAPA to YARA rule"
        reference = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/HardwareBreakpoints.cpp | michael.hunhoff@fireeye.com"
    strings:
        $GetThreadContext = "GetThreadContext"
        $CONTEXT_DEBUG_REGISTERS = { 10 00 01 00 }
        $DR0_access = { c7 45 ?? 00 00 00 00 }    // mov [ebp+var_X], 0x00000000
        $cmp_instr1 = { 3b c0 } // cmp eax, eax
        $cmp_instr2 = { 3b c1 } // cmp eax, ecx
        $cmp_instr3 = { 3b c2 } // cmp eax, edx
        $cmp_instr4 = { 3b c3 } // cmp eax, ebx

    condition:
        $GetThreadContext and $CONTEXT_DEBUG_REGISTERS and
        $DR0_access and (4 of ($cmp_instr*))
}

rule CheckForTrapFlagException {
    meta:
        name = "check for trap flag exception"
        author = "Teo-Prats"
        comment = "Converted from CAPA to YARA rule"
        reference = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/TrapFlag.cpp | michael.hunhoff@mandiant.com"
    strings:
        $pushf = { 9C }
        $popf = { 9D }
        $pushfd = { 66 9C }
        $popfd = { 66 9D }
        $pushfq = { 48 9C }
        $popfq = { 48 9D }
        $or_trap_flag = { 0B 24 ?? 00 01 }
        $bts_trap_flag = { 0F AB ?? 08 }

    condition:
        (any of ($pushf, $pushfd, $pushfq)) and
        (any of ($popf, $popfd, $popfq)) and
        (any of ($or_trap_flag, $bts_trap_flag))
}

rule NtYieldExecution_SwitchToThread_AntiDebug
{
    meta:
        description = "Detects the use of NtYieldExecution or SwitchToThread for anti-debugging purposes."
        author = "Teo-Prats"
        reference= "https://anti-debug.checkpoint.com/techniques/misc.html"

    strings:
        $nt_yield_execution = "NtYieldExecution"
        $switch_to_thread = "SwitchToThread"
        $status_no_yield_performed = { 24 00 00 40 }

    condition:
        
         $nt_yield_execution or $switch_to_thread or $status_no_yield_performed
        
}

rule VirtualAlloc_GetWriteWatch {
    meta:
        description = "Detects the use of VirtualAlloc and GetWriteWatch functions"
        author = "Teo-Prats"
        reference= "https://anti-debug.checkpoint.com/techniques/misc.html"
    strings:
        $virtualalloc = "VirtualAlloc" nocase wide ascii
        $getwritewatch = "GetWriteWatch" nocase wide ascii
    condition:
        any of them
}

rule CheckForInt3RetAntiDebug {
    meta:
        description = "Detects INT 3 and RET instructions used in a try-except block for anti-debugging"
        author = "Teo-Prats"
        reference = "https://unprotect.it/technique/call-to-interrupt-procedure/"

    strings:
        $int3_ret = { CD 03 C3 } // INT 03 followed by RET
        $seh_prologue = { 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 } // Example pattern for SEH prologue
        $seh_epilogue = { 64 89 0D 00 00 00 00 58 64 A3 00 00 00 00 } // Example pattern for SEH epilogue

    condition:
        $int3_ret and
        any of ($seh_prologue, $seh_epilogue)
}

rule DbgPrint_AntiDebug
{
    meta:
        description = "Detects the use of RaiseException with DBG_PRINTEXCEPTION_C for anti-debugging purposes."
        author = "Teo-Prats"
        reference ="https://anti-debug.checkpoint.com/techniques/misc.html"

    strings:
        $raise_exception = "RaiseException"
        $dbg_printexception_c = { 06 00 01 40 }  // Hexadecimal representation of DBG_PRINTEXCEPTION_C (0x40010006)

    condition:
        $raise_exception and $dbg_printexception_c
}

rule FuncIn {
    meta:
        description = "Detects malware loaders that download payloads from a C2 server"
        author = "Teo-Prats"
        reference = "https://unprotect.it/technique/funcin/"

    strings:
        $network_communication = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 } // Example pattern for push IP and call
        $http_request = "GET / HTTP/1.1" ascii
        $dns_api = "DnsQuery_A" ascii
        $load_library = "LoadLibrary" ascii
        $get_proc_address = "GetProcAddress" ascii
        $virtual_alloc = "VirtualAlloc" ascii
        $write_process_memory = "WriteProcessMemory" ascii
        $create_remote_thread = "CreateRemoteThread" ascii

    condition:
        any of ($network_communication, $http_request, $dns_api, $load_library, $get_proc_address, $virtual_alloc, $write_process_memory, $create_remote_thread)
}

rule RtlQueryProcessHeapInformation {
    meta:
        description = "Detects the use of RtlQueryProcessHeapInformation and related heap flag manipulations for anti-debugging"
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess"

    strings:
        $rtl_query_heap = "RtlQueryProcessHeapInformation" ascii
        $ntdll = "ntdll.dll" ascii
        $heap_flags_check = { 0F B7 45 ?? 3D ?? ?? 00 00 } // Example pattern for checking heap flags, assuming MOVZX and CMP
        $heap_flags_set = { C7 45 ?? ?? ?? ?? 00 00 } // Example pattern for setting heap flags, assuming MOV

    condition:
        
        all of ($rtl_query_heap, $ntdll) or any of ($heap_flags_check, $heap_flags_set)
}

rule DetectPEBBeingDebuggedFlagCheck {
    meta:
        name = "Detect PEB BeingDebugged Flag Check"
        description = "Detects reading the BeingDebugged flag from the PEB for anti-debugging"
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-peb-beingdebugged-flag"
    strings:
        // For 32-bit
        $fsdword = { 64 A1 30 00 00 00 }  // MOV EAX, FS:[30h]
        $being_debugged_32 = { 64 A1 30 00 00 00 8A 40 02 }  // MOV EAX, FS:[30h]; MOV AL, [EAX+2]

        // For 64-bit
        $gsqword = { 65 48 8B 04 25 60 00 00 00 }  // MOV RAX, GS:[60h]
        $being_debugged_64 = { 65 48 8B 04 25 60 00 00 00 0F B6 40 02 }  // MOV RAX, GS:[60h]; MOVZX EAX, BYTE PTR [RAX+2]

    condition:
        any of ($fsdword, $being_debugged_32, $gsqword, $being_debugged_64)
}

rule DetectHeapTailAndFreeCheckingFlags {
    meta:
        description = "Detects the presence of 0xABABABAB and 0xFEEEFEEE sequences indicative of heap tail and free checking flags"
        author = "Teo-Prats"
        reference = "o	https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-protection"

    strings:
        $heap_tail_checking_32 = { AB AB AB AB AB AB AB AB }  // 0xABABABAB twice for 32-bit
        $heap_tail_checking_64 = { AB AB AB AB AB AB AB AB AB AB AB AB AB AB AB AB }  // 0xABABABAB four times for 64-bit
        $heap_free_checking = { FE EE FE EE }  // 0xFEEEFEEE

    condition:
        any of ($heap_tail_checking_32, $heap_tail_checking_64, $heap_free_checking)
}

rule detect_desktop_switching {
    meta:
        description = "Detects potential desktop switching to evade debugging"
        author = "TeoPrats"
        reference= "https://anti-debug.checkpoint.com/techniques/interactive.html"
    strings:
        $desktop_check = "SwitchDesktop"
        $desktop_switch_api = "user32.dll"
        $desktop_event_check = /[\x10-\x1F]\x00\x00\x00..\x00\x00\x00\x00..\x00\x00\x00\x00\x00/
    condition:
        any of ($desktop_check, $desktop_switch_api) and $desktop_event_check
}

rule detect_OpenProcess{
    meta:
        description = "Detects calls to OpenProcess on csrss.exe potentially for debugging detection"
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/object-handles.html#openprocess"
    strings:
        $openProcess = "OpenProcess" wide ascii
        $csrss = "csrss.exe"
    condition:
        all of ($openProcess, $csrss)
}

rule DetectCreateFile {
    meta:
        description = "Detects the use of CreateFileW/CreateFileA to exclusively open the process file to detect debuggers"
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/object-handles.html#createfile"

    strings:
        $CreateFileW = "CreateFileW"
        $CreateFileA = "CreateFileA"
        $currentProcess = "\\Device\\HarddiskVolume" wide ascii

    condition:
        any of ($CreateFileW, $CreateFileA) and $currentProcess
}

rule DetectLoadLibraryCreateFileCheck {
    meta:
        description = "Detects the use of LoadLibraryA/W followed by CreateFileA/W to check for the presence of a debugger"
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/object-handles.html#loadlibrary"
    strings:
        $LoadLibraryA = "LoadLibraryA"
        $LoadLibraryW = "LoadLibraryW"
        $CreateFileA = "CreateFileA"
        $CreateFileW = "CreateFileW"
    condition:
        ($LoadLibraryA and $CreateFileA)
         or 
        ($LoadLibraryW and $CreateFileW)   
}

rule DetectRaiseExceptionDebuggerCheck {
    meta:
        description = "Detects the use of RaiseException to raise exceptions like DBG_CONTROL_C or DBG_RIPEVENT to check for the presence of a debugger"
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/exceptions.html#raiseexception"

    strings:
        $RaiseException = "RaiseException"
        $DBG_CONTROL_C = { 1D 00 00 00 } // DBG_CONTROL_C exception code
        $DBG_RIPEVENT = { 2D 00 00 00 } // DBG_RIPEVENT exception code

    condition:
        $RaiseException and ($DBG_CONTROL_C or $DBG_RIPEVENT)
}

rule DetectControlFlowHidingWithExceptions {
    meta:
        description = "Detects the use of a sequence of exception handlers to hide control flow"
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/exceptions.html"

    strings:
        $AddVectoredExceptionHandler = "AddVectoredExceptionHandler"
        $SetUnhandledExceptionFilter = "SetUnhandledExceptionFilter"
        $RaiseException = "RaiseException"
        $try = "__try"
        $except = "__except"

    condition:
        ($AddVectoredExceptionHandler and $RaiseException) or
        ($SetUnhandledExceptionFilter and $RaiseException) or
        ($try and $except and $RaiseException)       
}

rule DetectZwGetTickCount{
    meta:
        description = "Detects the usage of ZwGetTickCount() or direct reads from KUSER_SHARED_DATA as anti-debugging techniques"
        author = "Teo-prats"
        reference = "https://anti-debug.checkpoint.com/techniques/timing.html"
    strings:
        $ZwGetTickCount = "ZwGetTickCount"
        $KiGetTickCount = "KiGetTickCount"
        $KUSER_SHARED_DATA = { 7F FE 00 00 }  // Fixed address for KUSER_SHARED_DATA (0x7ffe0000)
    condition:
        $ZwGetTickCount or
        $KiGetTickCount or
        $KUSER_SHARED_DATA   
}

rule BlockInput_AntiDebug
{
    meta:
        description = "Detects the use of BlockInput for anti-debugging purposes."
        author = "TeoPrats"
        reference= "https://anti-debug.checkpoint.com/techniques/interactive.html"      

    strings:
        $block_input = "BlockInput"

    condition:
        any of them
}

rule Selector_Manipulation_AntiDebug
{
    meta:
        description = "Detects the use of selector manipulation for anti-debugging purposes."
        author = "Teo-Prats"
        reference="https://anti-debug.checkpoint.com/techniques/misc.html"

    strings:
        $xor_eax_eax = { 31 C0 }
        $push_fs = { 0F A0 }
        $pop_ds = { 1F }
        $xchg_eax_cl = { 86 08 }
        $int3 = { CC }
        $push_offset = { 68 ?? ?? ?? ?? }
        $pop_gs = { 0F A9 }
        $mov_fs_eax = { 64 89 20 }
        $cmp_al_3 = { 3C 03 }
        $je = { 74 ?? }

    condition:
        all of ($xor_eax_eax, $push_fs, $pop_ds, $xchg_eax_cl) or
        all of ($push_offset, $int3, $pop_gs, $mov_fs_eax, $cmp_al_3, $je)
        
}

rule StackSegmentRegister {
    meta:
        description = "Detects the anti-debugging technique that checks for the Trap Flag by using push ss, pop ss, and pushf instructions"
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/assembly.html"

    strings:
        $sequence = { 16 1F 9C }  // Corresponding byte sequence for "push ss; pop ss; pushf"

    condition:
        $sequence
}

rule DetectInstructionPrefixesAntiDebug {
    meta:
        description = "Detects the anti-debugging technique that uses instruction prefixes"
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/assembly.html"

    strings:
        $prefix_int1_sequence = { F3 64 F1 }  // PREFIX REP: and INT1 instruction

    condition:
        $prefix_int1_sequence
}

rule Self_Debugging_Detection
{
    meta:
        description = "Detects the use of self-debugging techniques in a binary."
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/interactive.html#self-debugging"        
    strings:
        $debug_active_process = { 44 65 62 75 67 41 63 74 69 76 65 50 72 6F 63 65 73 73 }    // "DebugActiveProcess"
        $create_event_w = { 43 72 65 61 74 65 45 76 65 6E 74 57 }                            // "CreateEventW"
        $get_module_file_name_w = { 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 57 } // "GetModuleFileNameW"
        $is_debugged_function = { 49 73 44 65 62 75 67 67 65 64 }                           // "IsDebugged"
        $enable_debug_privilege = { 45 6E 61 62 6C 65 44 65 62 75 67 50 72 69 76 69 6C 65 67 65 } // "EnableDebugPrivilege"
    condition:
       any of($debug_active_process,
        $create_event_w,
        $get_module_file_name_w,
        $is_debugged_function,
        $enable_debug_privilege)     
}

rule GenerateConsoleCtrlEvent_AntiDebug
{
    meta:
        description = "Detects the use of GenerateConsoleCtrlEvent for anti-debugging purposes."
        author = "Teo-Prats"
        reference = "https://anti-debug.checkpoint.com/techniques/interactive.html"
    strings:
        $generate_console_ctrl_event = { 47 65 6E 65 72 61 74 65 43 6F 6E 73 6F 6C 65 43 74 72 6C 45 76 65 6E 74 }  // "GenerateConsoleCtrlEvent"
        $dbg_control_c = { 44 42 47 5F 43 4F 4E 54 52 4F 4C 5F 43 }  // "DBG_CONTROL_C"
        $add_vectored_exception_handler = { 41 64 64 56 65 63 74 6F 72 65 64 45 78 63 65 70 74 69 6F 6E 48 61 6E 64 6C 65 72 }  // "AddVectoredExceptionHandler"
        $set_console_ctrl_handler = { 53 65 74 43 6F 6E 73 6F 6C 65 43 74 72 6C 48 61 6E 64 6C 65 72 }  // "SetConsoleCtrlHandler"
        $remove_vectored_exception_handler = { 52 65 6D 6F 76 65 56 65 63 74 6F 72 65 64 45 78 63 65 70 74 69 6F 6E 48 61 6E 64 6C 65 72 }  // "RemoveVectoredExceptionHandler"
    condition:
        $generate_console_ctrl_event or
        $dbg_control_c      
}














