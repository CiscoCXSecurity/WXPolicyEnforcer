# W^X Poilicy Enforcer

This project is a proof of concept (PoC) which implements a W^X policy on memory pages within a process within Windows. W^X means that no page can be marked both writable or executable, though in this case further care is taken to ensure that any page which has been marked as writable can never be marked as executable.

The enforcement module is a DLL which can be injected into any process, either x86-32 or x86-64, and works by hooking memory management APIs. The work is done within DLLMain, so no API needs to be called by the application. I personally use Cheat Engine's DLL inject feature for testing, though this can be deployed system-wide using AppInit_DLLs or a similar measure.

## Code

The main code can be found in WXPolicyEnforcer/main.cpp, which performs all of the actual logic related to W^X policy enforcement. The mhook library is used to do the hooking, although it needed to be patched slightly to work on x86-64 executables under Windows 10 (a pull request is now pending on the original project to include this fix upstream).

The functions hooked are: VirtualAlloc, VirtualProtect, VirtualFree. Calls to VirtualAlloc or VirtualProtect directly asking for PAGE_EXECUTE_READWRITE are denied automatically. Calls to VirtualProtect where the affected pages' previous protection was writable, and where the requested page protection is now executable, are denied. Calls to VirtualProtect which affect pages which have ever been seen by the DLL to be marked as writable are also rejected if the requested protection is executable. This prevents tricks like marking a page as read-write, then read-only, then read-execute, where a more naive check would not "remember" the original read-write status of the pages.

The git repo for the mhook library [can be found here](https://github.com/martona/mhook). It includes disasm-lib by Matt Conover.

## Known weaknesses

There are a few known weaknesses to this approach from an exploit mitigation perspective:

* It breaks anything that does JIT. This is the major one - anything that uses .NET or JavaScript will break.
* Directly calling NtAllocateVirtualMemory or NtProtectVirtualMemory from ntdll.dll will bypass the hooks and allow for violation of the W^X policy. This could be easily remedied by hooking those APIs too, though this has not been done in this PoC.
* There are likely edge-cases with unaligned address and size values being passed to the APIs, such that someone could potentially avoid W^X enforcement for certain pages in a larger allocation. I have not fully verified the maths and logic.

## Findings

The following applications, during my testing, violated the W^X policy and either crashed or broke in some way:

* Spotify (works until accessing Browse, Radio, Your Daily Mix, or other similar features)
* Firefox
* Chrome
* MPC-HC (works until attempting to open a file)

The following applications, during my testing, appeared to work fine with W^X policy enforcement:

* VLC Media Player (64-bit)
* Notepad
* Paint

This is mostly just for the sake of interest.