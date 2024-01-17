; struct SSN_INFO *__cdecl RTL_FRAME<struct SSN_INFO>::get(void)
extern ?get@?$RTL_FRAME@USSN_INFO@@@@SAPEAUSSN_INFO@@XZ : PROC

SSN_INFO STRUCT
	_M_apiAddr DQ ?
	_M_pTable DQ ?
	_M_apiSSN DD ?
	_M_N DD ?
	_M_TargetSSN DD ?
SSN_INFO ENDS

.code

?Stub@@YAXXZ proc
	mov [rsp+8],rcx
	mov [rsp+10h],rdx
	mov [rsp+18h],r8
	mov [rsp+20h],r9
	
	call ?get@?$RTL_FRAME@USSN_INFO@@@@SAPEAUSSN_INFO@@XZ
	
	mov r9,[rsp+20h]
	mov r8,[rsp+18h]
	mov rdx,[rsp+10h]
	mov rcx,[rsp+8]

	mov rax,[rax + SSN_INFO._M_apiAddr]
	pushf
	or DWORD PTR [rsp],100h
	popf
	jmp rax
	
?Stub@@YAXXZ endp

end