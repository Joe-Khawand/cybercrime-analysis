import pefile
import argparse

def check_pe_properties(pe):
    print('\033[92m'+f"File {file_path} is a PE file."+'\033[0m')
    print(f"Is a DLL: {pe.is_dll()}")

    if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') :
        print("The file is signed with  : %s " % pe.get_data(pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress, pe.DIRECTORY_ENTRY_SECURITY.Size))
    else:
        print('\033[91m'+"The file has no signature"+'\033[0m')

    print("The file has a rich header: "+str(pe.RICH_HEADER!=None))
    print(f"IMAGE_FILE_HEADER Timestamp: {pe.FILE_HEADER.TimeDateStamp}")

    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        print('\033[92m'"The file contains debug directory"+'\033[0m')
        debug_directories = pe.DIRECTORY_ENTRY_DEBUG
        for debug_directory in debug_directories:
            debug_type = debug_directory.struct.Type
            debug_timestamp = debug_directory.struct.TimeDateStamp
            print(f"Debug Type: {debug_type}")
            print(f"Debug Timestamp: {debug_timestamp}")
    else:
        print('\033[91m'+"Does not contain debug directory."+'\033[0m')

if __name__ == '__main__':
    print('\033[95m'+"Pe file analysis"+'\033[0m')
    parser = argparse.ArgumentParser(description='Check properties of a PE file.')
    parser.add_argument('file', type=str, help='Path to the PE file')
    args = parser.parse_args()
    file_path = args.file

    try:
        pe = pefile.PE(file_path)
        check_pe_properties(pe)
    except OSError as e:
        print(e)
    except pefile.PEFormatError:
        print('\033[91m'+f"File {file_path} is not a PE file."+'\033[0m')
