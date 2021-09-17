fn main() {
    windows::build!(
        Windows::Win32::System::Threading::{CreateProcessA,NtQueryInformationProcess,ResumeThread,STARTUPINFOA,PROCESS_INFORMATION,PROCESS_CREATION_FLAGS,PROCESSINFOCLASS,PROCESS_BASIC_INFORMATION},
        Windows::Win32::Security::SECURITY_ATTRIBUTES, 
        Windows::Win32::Foundation::PSTR,
        Windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory,WriteProcessMemory},
        Windows::Win32::System::Memory::{VirtualProtectEx,PAGE_PROTECTION_FLAGS},   
    );
}