## Von-Neumann architecture:
```
Primary memory   - CPU cache & RAM
Secondary memory - Drives, CD-ROMS, Floppys and stuff

CU   - Control Unit - responsible for io with ram and peripheral devices, interrupt control & monitoring of the entire system
ALU  - Arythmetic and Logic Unit - responsible for the actual calculations ?? 
IR   - Instruction Register - the CU contains the IR - this is the list of processor instructions
IAR  - Instruction Address Register
ISA  - Instruction Set Architecture - instruction set corresponding to a given proc architecture - e.g. arm x86 and so on ... 
```

## Instruction Set Architectures types: 
```
CISC - Complex Instruction Set Computing
RISC - Reduced Instruction Set Computing
VLIW - Very Long Instruction Word
EPIC - Explicitly Parallel Instruction Computing
```

## Instruction Cycle:
```
1. FETCH                           The next address is read from IAR. It is then loaded from the Cache or RAM into the Instruction Register (IR).
2. DECODE                          The instruction decoder converts the instructions and starts the necessary circuits to execute the instruction.
3. FETCH OPERANDS                  If further data have to be loaded for execution, these are loaded from the cache or RAM into the working registers.
4. EXECUTE                         The instruction is executed. 
5. UPDATE INSTRUCTION POINTER      If no jump at EXECUTE phase, the IAR is increased by the length of the instruction and points to next machine instruction.
```

## Binary formats;
```
ELF  - Executable & Linking Format - (Nix)
PE   - Portable Executable Format  - (Windows)
```

## Memory structure:
```
stack - grows down (like stalactites) - LIFO - last in first out - return address, parameters, frame pointers 
heap  - grows up (like stalactites) - dynamically allocated program memory
.bss  - statically allocated variables represented exclusively by 0 bits
.data - global and static variables that are explicitly initialized by the program.
.text - the actual assembler instructions of the program. RO
```

## Modern memory protections:
```
ASLR - Address Space Layout Randomization
DER  - Data Execution Prevention - marks some addresses as non exec
```

## Disable ASLR
```
echo 0 > /proc/sys/kernel/randomize_va_space  # Was 2
sudo apt install gcc-multilib
gcc bow.c -o bow32 -fno-stack-protector -z execstack -m32
```

## Vulnerable C Functions 
```
strcpy
gets
sprintf
scanf
strcat
```

## GDB
```
gdb -q bow32
disassemble main
set disasembly-flavor intel
disassemble main
echo 'set disassembly-flavor intel' > ~/.gdbinit
```

## Intel flavor Anatomy 
```
   0x000011e2 <+0>:     lea    ecx,[esp+0x4]
   ---------- ----      ---    -------------
        1       2        3           4
```

1. Memory address 
2. Address jumps in memory (in bytes)
3. Assembler instructions 
4. Operation Suffixes 

## Data Registers
|32-bit  |64-bit |Description|
|--------|-------|-----------|
|EAX     |RAX    |Accumulator is used in input/output and for arithmetic operations|
|EBX     |RBX    |Base is used in indexed addressing|
|ECX     |RCX    |Counter is used to rotate instructions and count loops|
|EDX     |RDX    |Data is used for I/O and in arithmetic operations for multiply and divide operations involving large values|

## Pointer Registers
|32-bit  |64-bit |Description|
|--------|-------|-----------|
|EIP     |RIP    |Instruction Pointer stores the offset address of the next instruction to be executed|
|ESP     |RSP    |Stack Pointer points to the top of the stack|
|EBP     |RBP    |Base Pointer is also known as Stack Base Pointer or Frame Pointer thats points to the base of the stack|

## Index Registers
|32-bit  |64-bit |Description|
|--------|-------|-----------|
|ESI     |RSI    |Source Index is used as a pointer from a source for string operations|
|EDI     |RDI    |Destination is used as a pointer to a destination for string operations|

