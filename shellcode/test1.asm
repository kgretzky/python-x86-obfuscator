use32
org 0h

  cld
  mov cl, 5
  cmp ah, 2
  jnz start
  mov ax, 8888h
start:
  mov edx, 11223344h
  loop start
;  xor edx, edx