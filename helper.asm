;*********************************
; Author     => Abdallah Mohamed
; Date       => 14-5-2023/11:11PM
; Greetz to  => Hossam Ehab
;*********************************

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

end