use32
org 0h

  cld
  mov cl, 5
  cmp ah, 2
  jnz start
  mov ax, 8888h
  push 0cafebabeh
  push 0
  push 22h
  push 8888h
start:
  mov edx, 11223344h
  mov edi, [fs:eax+30h]
  mov dl, byte [ecx+2]
  mov edx, [ecx+2]
  mov edx, [ecx+4444h]
  mov dx, word [ecx+4444h]
  mov ecx, [edx+esi+88h]
  mov ecx, [edx+esi-88h]
  mov ecx, [edx+esi-12h]
  mov ecx, [edx+esi+8888h]
  mov ecx, [edx+esi*2+88h]
  nop
  cmp byte [edx+esi*4+80], bl
  cmp byte [edx+esi*4+80], 0ffh
  cmp word [edx+esi*4+80], 0ff88h
  cmp dword [edx+esi*4+80], 0ffffh
  cmp dword [edx+esi*4+80], 80h
  cmp dword [edx+esi*4+80], -12h
  cmp dword [edx+esi*4], 0ffffh
  cmp dword [edx+esi], 0ffffh
  cmp dword [edx], 0ffffh
  cmp edx, 88h
  loop start
;  xor edx, edx