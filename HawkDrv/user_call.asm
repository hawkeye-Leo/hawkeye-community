;
; HawkKiCallUserMode2
;
;   rcx = ReturnValuePointer (&returnSlot)
;   rdx = PHAWK_CALL_USER_DATA { LandingStub, UserSyntheticStack, TargetFunction }
;   r8  = KernelStackControl (= KernelStackTop - HAWK_ASM_KERNEL_STACK_CONTROL)
;
; Pool layout (high -> low):
;   r8 + CONTROL              KernelStackTop / KTHREAD->StackBase
;   [r8, r8 + CONTROL)        control block
;   [r8 - SCRATCH, r8)        scratch; OutputLength qword at r8 - SCRATCH
;
; NtCallbackReturn (Win11, verified):
;   r10 = KTHREAD->InitialStack (= r8)
;   r9  = [r10 + 20h]         RSP of 0x138 frame on IOCTL stack
;   restore TrapFrame / KTHREAD stack / gs or TSS anchors
;   mov rsp, r9; restore XMM+GP; add rsp, 138h; ret to Call6
;
; Equates — keep in sync with usermode_callback.h.
HAWK_ASM_KERNEL_STACK_SIZE      equ 6000h
HAWK_ASM_KERNEL_STACK_CONTROL   equ 50h
HAWK_ASM_KERNEL_STACK_SCRATCH   equ 30h
HAWK_ASM_CALLBACK_STACK_HEAD    equ (HAWK_ASM_KERNEL_STACK_CONTROL + HAWK_ASM_KERNEL_STACK_SCRATCH)
        .code
        extern g_HawkAsmKvaShadow:qword
        extern g_HawkAsmStackGsOffset:qword
        public HawkKiCallUserMode2
HawkKiCallUserMode2 PROC
; --- IOCTL stack: 0x138 frame for NtCallbackReturn ---
        sub     rsp, 0138h
        movaps  xmmword ptr [rsp + 30h], xmm6
        movaps  xmmword ptr [rsp + 40h], xmm7
        movaps  xmmword ptr [rsp + 50h], xmm8
        movaps  xmmword ptr [rsp + 60h], xmm9
        movaps  xmmword ptr [rsp + 70h], xmm10
        lea     rax, [rsp + 100h]
        movaps  xmmword ptr [rax - 40h], xmm15
        movaps  xmmword ptr [rax - 50h], xmm14
        movaps  xmmword ptr [rax - 60h], xmm13
        movaps  xmmword ptr [rax - 70h], xmm12
        movaps  xmmword ptr [rax - 80h], xmm11
        mov     qword ptr [rax - 8], rbp
        mov     rbp, rsp
        mov     qword ptr [rax], rbx
        mov     qword ptr [rax + 8], rdi
        mov     qword ptr [rax + 10h], rsi
        mov     qword ptr [rax + 18h], r12
        mov     qword ptr [rax + 20h], r13
        mov     qword ptr [rax + 28h], r14
        mov     qword ptr [rax + 30h], r15
; --- Publish return metadata (consumed by NtCallbackReturn on the way back) ---
        mov     rbx, qword ptr gs:[188h]      ; current KTHREAD
        mov     rsi, qword ptr [rbx + 90h]    ; IOCTL TrapFrame (sysret field source)
        mov     qword ptr [rbp + 0D0h], rsi   ; frame+0xD0: restore KTHREAD->TrapFrame
        mov     qword ptr [rbp + 0D8h], rcx   ; frame+0xD8: PostCall stores user output VA -> returnSlot
        lea     rax, [r8 - HAWK_ASM_KERNEL_STACK_SCRATCH]
        mov     qword ptr [rbp + 0E0h], rax   ; frame+0xE0: PostCall stores OutputLength -> scratch
        mov     qword ptr [r8 + 20h], rsp     ; control+0x20: RSP of this 0x138 frame (NtCallbackReturn rsp)

; --- Switch KTHREAD to callback pool stack (cli: atomic with gs/TSS below) ---
        cli
        mov     qword ptr [rbx + 28h], r8     ; InitialStack = kernelStackControl
        lea     r9, [r8 + HAWK_ASM_KERNEL_STACK_CONTROL]
        mov     qword ptr [rbx + 38h], r9     ; StackBase = pool top (nested syscalls ceiling)
        mov     ecx, HAWK_ASM_KERNEL_STACK_SIZE
        sub     r9, rcx
        mov     qword ptr [rbx + 30h], r9     ; StackLimit = pool top - POOL

; --- Per-CPU stack anchors = r8 (GDI etc. re-enter kernel on pool stack during callback) ---
        mov     rax, qword ptr g_HawkAsmKvaShadow
        cmp     rax, 0
        je      hawk_no_kva_shadow
        mov     eax, dword ptr g_HawkAsmStackGsOffset
        mov     gs:[eax], r8                  ; KVA shadow: syscall stack anchor
        jmp     hawk_kva_shadow_done
hawk_no_kva_shadow:
        mov     rdi, qword ptr gs:[8]
        mov     qword ptr [rdi + 4], r8       ; TSS.Rsp0: interrupt stack anchor
hawk_kva_shadow_done:
        mov     gs:[1A8h], r8                 ; KPRCB: syscall re-entry anchor (= control)

; --- sysret: land on user landing stub + synthetic stack (see callData in rdx) ---
        ldmxcsr dword ptr [rsi + 2Ch]         ; restore MXCSR from IOCTL TrapFrame
        mov     r11, qword ptr [rsi + 178h]   ; user EFlags -> sysret r11
        mov     rbp, qword ptr [rsi + 158h]   ; user RBP from TrapFrame
        mov     rax, qword ptr [rdx + 10h]    ; TargetFunction -> sysret rax (stub jmp target)
        mov     rsp, qword ptr [rdx + 8]      ; switch to user synthetic stack
        mov     rcx, qword ptr [rdx]          ; LandingStub -> sysret rcx (RIP)
        swapgs
        sysretq                               ; enter user mode at LandingStub
HawkKiCallUserMode2 ENDP
        end
