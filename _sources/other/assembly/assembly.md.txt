# Assembly

## Syntax variants 
```
GAS  - uses the AT&T syntax a relatively archaic syntax
NASM - uses the Intel syntax
```

## GAS example (AT&T)

A simple program that exits 2
```gas
.section .data
.section .text
.globl _start

_start:
    movl $1, %eax
    movl $2, %ebx
    int $0x80
```

use the as compiler, and ld linker
```bash
as -o exit.o exit.s
ld -o exit exit.o 
```


## NASM example (Intel)

A simple program that exits 2
```nasm
section .data
section .text
global _start

_start:
    mov eax,1
    mov ebx,2
    int 80h
```

use the nasm compiler, and ld linker
```bash
nasm -f elf32 -o exit.o exit.asm
ld -m elf_i386 -o exit exit.o 
```


## Write Hello World in x86 Intel assembly

```nasm
section .text:

global _start

_start:
    ; as per instructions in the man 2 write page
    mov eax, 0x4              ; use the write syscall -> number 4
    mov ebx, 1                ; use stdout for the fd
    mov ecx, message          ; use the message as the buffer
    mov edx, message_length   ; and supply the length
    int 0x80                  ; interupt the program an run our write syscall

    ; now gracefully exit
    mov eax, 0x1
    mov ebx, 0
    int 0x80

section .data:
    message: db "Hello World!", 0xA  ; db -> define bytes, message is the name of the variable
                                     ; 0xA hex = 10 ordinal = \n char
    message_length equ $-message     ; $- notation will be dynamically interpreted
                                     ; by nasm as the length of the message variale
```

find the docs for what we're talking about
```bash
/usr/include/x86_64-linux-gnu/asm/unistd_32.h
man 2 write
man 2 exit 
```

compile
```bash
nasm -f elf32 -o hello-world.o hello-world.asm
ld -m elf_i386 -o hello-world hello-world.o 
```
