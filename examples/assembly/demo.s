# SPDX-License-Identifier: GPL-3.0-or-later
# GNU assembler, Intel syntax, x86-64. No network or external dependencies.
.intel_syntax noprefix

.section .text
.global _start, check_gate, patch_pad
.ifndef PE
.type _start, @function
.type check_gate, @function
.endif
_start:
    call check_gate
.ifdef PE
    # Inspection fixture only. No Windows imports or runtime are provided.
    ret
.else
    test eax, eax
    jz denied
    lea rsi, [rip + granted_message]
    mov edx, OFFSET granted_length
    jmp print_message
denied:
    lea rsi, [rip + denied_message]
    mov edx, OFFSET denied_length
print_message:
    mov edi, 1
    mov eax, 1
    syscall
    xor edi, edi
    mov eax, 60
    syscall
.endif

check_gate:
    movzx eax, byte ptr [rip + demo_gate]
    ret
.ifndef PE
.size check_gate, . - check_gate
.endif

# A NOP workspace that is not on the executed path.
patch_pad:
    .fill 16, 1, 0x90

.section .rodata
.global demo_magic, number_le, signed_value, greeting_utf8, greeting_latin1
.global greeting_utf16le, greeting_utf16be, signature_lab, entropy_ramp, zero_pad
.global granted_message, denied_message

demo_magic:
    .asciz "DZ6DEMO"
number_le:
    .long 0x12345678
signed_value:
    .long -42
greeting_utf8:
    .asciz "Hello, dz6! Olá, Brasil!"
greeting_latin1:
    .ascii "Ol"
    .byte 0xe1, 0
greeting_utf16le:
    .byte 0x4f,0,0x6c,0,0xe1,0,0,0
greeting_utf16be:
    .byte 0,0x4f,0,0x6c,0,0xe1,0,0
    .asciz "FindMe findme FINDME"
    .asciz "DEMO_TAG:alpha"
    .asciz "DEMO_TAG:beta"
    .asciz "DEMO_TAG:gamma"
granted_message:
    .ascii "Access granted\n"
.set granted_length, . - granted_message
    .byte 0
denied_message:
    .ascii "Access denied!\n"
.set denied_length, . - denied_message
    .byte 0
signature_lab:
    .byte 0xde,0xad,0xbe,0xef,0xa1,0x5a,0x11,0x22,0xbb
    .byte 0xaa,0xaa,0xaa
entropy_ramp:
.set counter, 0
.rept 256
    .byte counter
    .set counter, counter + 1
.endr
zero_pad:
    .fill 256, 1, 0

.section .data
.global demo_gate
demo_gate:
    .byte 0

.section .bss
.global scratch_buffer
scratch_buffer:
    .skip 64

.ifndef PE
.section .note.GNU-stack,"",@progbits
.endif
