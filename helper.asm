;***************************************************
; Author     => Abdallah Mohamed ( 0xNinjaCyclone )
; Date       => 14-5-2023/11:11PM
; Greetz to  => Hossam Ehab
;***************************************************

.code

;************************
; Get Image base address
;************************
GetImgBaseAddr proc
	call $+5                  ; Call the next instruction
	pop rax                   ; Get current instruction address
	mov di, 5A4Dh             ; PE magic number
	
	; Search backward until find image magic number
	FIND_MAGIC:
	dec rax                   ; Go backwards
	mov si, word ptr [rax]    ; Move current image bytes to si for comparison
	cmp si, di                ; *pCurrentAddr == IMAGE_DOS_SIGNATURE ?
	jne FIND_MAGIC

	; We have found 'MZ', but we must check NT Headers signature
	mov ebx, [rax + 3Ch]      ; NT Headers RVA

	; Some checks to avoid a bogus signature
	mov ecx, 40h              ; sizeof(IMAGE_DOS_HEADER)
	cmp ebx, ecx              ; DOS->e_lfanew <= sizeof(IMAGE_DOS_HEADER)  
	jle FIND_MAGIC

	mov ecx, 400h             ; 1024
	cmp ebx, ecx              ; DOS->e_lfanew > 1024
	jg FIND_MAGIC

	push di                   ; Save PE magic number
	mov edi, 00004550h        ; NT Headers Signature
	add rbx, rax              ; BaseAddress + DOS->e_lfanew
	mov esi, dword ptr [rbx]  ; ( PIMAGE_NT_HEADERS )->Signature 
	cmp esi, edi              ; Signature == IMAGE_NT_SIGNATURE ?
	pop di                    ; Restore PE magic number
	jne FIND_MAGIC            ; So far

	;**************************************
	; We have found the image base address
	;**************************************

	ret
GetImgBaseAddr endp

;**********************************************
; Resolve imported function address by ordinal
;**********************************************
ResolveAddrByOrdinal proc
	xchg rcx, rdx                       ; Swap(BaseAddress, ordinal)
	xor rax, rax                        ; Clear accumlator reg
	mov eax, dword ptr [rdx + 3Ch]      ; NT Headers RVA
	add rax, rdx                        ; BaseAddress + NT_RVA
	mov eax, dword ptr [rax + 88h]      ; Export Dir RVA
	test rax, rax                       ; Maybe there are no exports
	jz NOEXPORTS                        ; Tell the caller we failed
	add rax, rdx                        ; Jump on the export table
	sub ecx, dword ptr [rax + 10h]      ; Ordinal - pDir->Base

	; We have to ensure that we rely on a valid ordinal
	push rcx                            ; Save the ordinal
	xor rcx, rcx                        ; Clear counter reg
	mov cx, word ptr [rax + 18h]        ; Number of entries
	cmp dword ptr [rsp], ecx            ; The ordinal out of the image ordinals range
	jge INVALID_ORDINAL                 ; Tell the caller we failed

	; Find the import name
	mov rdi, r8                         ; Imported name reference
	xor r9, r9                          ; Clear the register
	mov r9d, dword ptr [rax + 24h]      ; Image ordinals RVA
	add r9, rdx                         ; Jump on the ORD table
	FIND_NAME_INDEX:
	dec rcx                             ; We search backward
	mov si, word ptr [r9 + 2h * rcx]    ; Retreive current ordinal
	cmp si, word ptr [rsp]              ; Check if that the target one
	je FOUND                            ; Let's move on to the next step
	test rcx, rcx                       ; Check if we've reached the end of the table
	jnz FIND_NAME_INDEX                 ; Keep digging

	; WHAT THE FUCK IF THE ORDINAL DOESN'T EXIST WITHIN THE TABLE!
	jmp INVALID_ORDINAL

	FOUND:
	mov r8d, dword ptr [rax + 20h]      ; Names RVA
	add r8, rdx                         ; Add BaseAddress
	mov ebx, dword ptr [r8 + 4h * rcx]  ; Get target name RVA
	add rbx, rdx                        ; Add BaseAddress
	mov [rdi], rbx                      ; Set the name reference
	
	; Get the imported function address
	pop rcx                             ; pop off the ordinal from the stack
	mov r8d, dword ptr [rax + 1Ch]      ; EAT RVA
	add r8, rdx                         ; Jump on the EAT
	mov eax, [r8 + 4h * rcx]            ; Required address RVA
	add rax, rdx                        ; Get Imported function address

	FINISH:
	ret

	INVALID_ORDINAL:
	pop rcx

	NOEXPORTS:
	xor rax, rax
	jmp FINISH

ResolveAddrByOrdinal endp

end