; void *__cdecl SyscallNum(unsigned long)
extern ?SyscallNum@@YAPEAXK@Z : PROC

NtApi MACRO hash, name
@CatStr(@@,name) proc
	mov eax,hash
	jmp ?SetIndex@
@CatStr(@@,name) endp
ENDM

NtImp MACRO name
@CatStr(__imp_Nt,name) DQ @CatStr(@@,name)
public @CatStr(__imp_Nt,name)
ENDM

.code

?SetIndex@ proc
	mov [rsp+8],rcx
	mov [rsp+10h],rdx
	mov [rsp+18h],r8
	mov [rsp+20h],r9
	
	sub rsp,28h
	mov ecx,eax
	call ?SyscallNum@@YAPEAXK@Z
	add rsp,28h
	
	mov r9,[rsp+20h]
	mov r8,[rsp+18h]
	mov rdx,[rsp+10h]
	mov rcx,[rsp+8]

	pushf
	or DWORD PTR [rsp],100h
	popf
	jmp rax
	
?SetIndex@ endp

NtApi 0334977c3h, OpenKey 
NtApi 05aabc376h, QueryValueKey
NtApi 004d4d176h, Close 

.const

NtImp OpenKey
NtImp QueryValueKey
NtImp Close

end