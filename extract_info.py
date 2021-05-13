import pefile


def file_features(file_path: str) -> dict:
    res = {}
    pe = pefile.PE(file_path)

    # DOS_HEADER
    res['e_magic'] = pe.DOS_HEADER.e_magic
    res['e_cblp'] = pe.DOS_HEADER.e_cblp
    res['e_cp'] = pe.DOS_HEADER.e_cp
    res['e_crlc'] = pe.DOS_HEADER.e_crlc
    res['e_cparhdr'] = pe.DOS_HEADER.e_cparhdr
    res['e_minalloc'] = pe.DOS_HEADER.e_minalloc
    res['e_maxalloc'] = pe.DOS_HEADER.e_maxalloc
    res['e_ss'] = pe.DOS_HEADER.e_ss
    res['e_sp'] = pe.DOS_HEADER.e_sp
    res['e_csum'] = pe.DOS_HEADER.e_csum
    res['e_ip'] = pe.DOS_HEADER.e_ip
    res['e_cs'] = pe.DOS_HEADER.e_cs
    res['e_lfarlc'] = pe.DOS_HEADER.e_lfarlc
    res['e_ovno'] = pe.DOS_HEADER.e_ovno
    res['e_oemid'] = pe.DOS_HEADER.e_oemid
    res['e_oeminfo'] = pe.DOS_HEADER.e_oeminfo
    res['e_lfanew'] = pe.DOS_HEADER.e_lfanew

    # FILE_HEADER
    res['Machine'] = pe.FILE_HEADER.Machine
    res['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
    res['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
    res['PointerToSymbolTable'] = pe.FILE_HEADER.PointerToSymbolTable
    res['NumberOfSymbols'] = pe.FILE_HEADER.NumberOfSymbols
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics

    # OPTIONAL_HEADER
    res['Magic'] = pe.OPTIONAL_HEADER.Magic
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    entropy = map(lambda x: x.get_entropy(), pe.sections)
    if not entropy:
        res['SectionsMinEntropy'] = min(entropy)
        res['SectionsMaxEntropy'] = max(entropy)
    else:
        res['SectionsMinEntropy'] = 0
        res['SectionsMaxEntropy'] = 0

    raw_sizes = map(lambda x: x.SizeOfRawData, pe.sections)
    if not raw_sizes:
        res['SectionsMinRawsize'] = min(raw_sizes)
        res['SectionsMaxRawsize'] = max(raw_sizes)
    else:
        res['SectionsMinRawsize'] = 0
        res['SectionsMaxRawsize'] = 0

    virtual_sizes = map(lambda x: x.Misc_VirtualSize, pe.sections)
    if not raw_sizes:
        res['SectionsMinVirtualsize'] = min(virtual_sizes)
        res['SectionMaxVirtualsize'] = max(virtual_sizes)
    else:
        res['SectionsMinVirtualsize'] = 0
        res['SectionMaxVirtualsize'] = 0

    return res
