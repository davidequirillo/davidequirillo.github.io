---
layout: post
title: TryHackMe - "Flag Vault" (v1 and v2)
categories: Challenges
tags: red-team pen-testing 
---
[Link to the challenge (ver. 1)](https://tryhackme.com/room/hfb1flagvault) \
[Link to the challenge (ver. 2)](https://tryhackme.com/room/hfb1flagvault2)

## Introduction
When we think to buffer overflow and format string attacks, we immediately imagine having to take control the target machine using a shellcode or similar.

However, these attacks are very rare today because modern operating systems have protections against the possibility of executing code within the stack or heap (NX protection). 
They have ASLR too, a defense mechanism thanks to which the addresses of stack, heap and functions are randomized at each execution. 
Finally, there is the technique of inserting a "canary" into stack frames as an additional trick, in order to check that stack is not altered, in the case of partial success of these two attacks.
In a few words: simply put, today's computers are well protected (as long as they are updated, of course).

Despite these powerful defenses, if the program is vulnerable, there is always the possibility of stealing data (perhaps authentication) or modifying the behavior of the program in some way, by making buffer overflow and/or format string attacks, which sometimes can also be relatively simple, as in these two cases discussed in this article.

## Case n. 1 (buffer overflow)

In the first case, analyzing the source code (written in C language) of the program that runs on the server, we see that in "login" function, which implement user authentication, only username is requested (there is no option to enter the password, so the login always fails). 
But the vulnerability is immediately noticeable, because although the "username" variable allows the insertion of a maximum of 100 characters, in the "gets" function (that requests input from the user's keyboard), there is no check to ensure that this limit is exceeded, so if the client as "username" enters a string that exceeds 100 characters, the extra characters overwrite other locations in the current frame of the stack (the login function frame).

Here, in the stack frame in question, "password" variable is located immediately after "username" variable, so it is quite easy to create a payload that allows us to successfully authenticate (managing to enter username and password written in the source), passing the challenge.
Remember that the challenge has the goal of not authenticating the user (saying that the server is "passwordless"), but let's demonstrate that by performing a buffer overflow attack we can overcome this constraint.

We compile our program with source code debugging support:

`gcc -g -O0 -std=c99 pwn1.c -o pwn`

By loading our program with gdb, and setting some breakpoints, we can study the stack frame appearance when we are in the login function, before inserting "username" string from our keyboard, and after inserting it.

We do not report the various steps, and leave these various tests to the reader.

By inserting a very long string from the keyboard, we notice it overwrites memory locations that contain password, in the stack frame.

Therefore, by forging an appropriate payload, we can forcefully insert into the two memory segments involved (username and password) the correct strings ​​reported in the source file, in order to successfully pass the authentication check.

The following python script, is used to build our payload (payload.bin)

    username_bytes = "bytereaper".encode('UTF-8')
    password_bytes = "5up3rP4zz123Byte".encode('UTF-8')
    payload = username_bytes
    payload += b"\x00" * (100 - len(username_bytes)) 
    payload += b"\x00"*12 # for alignment purpose
    payload += password_bytes
    payload += b"\x00" * (100 - len(password_bytes))

    with open("payload.bin", "wb") as f:
        f.write(payload)

Now that we have the payload, we can send it to the server, thus obtaining the challenge flag as output:

`(cat payload.bin; echo) | nc flag-vault.tryhackme.local 1337`

## Case n. 2 (format string)

Now let's see the second version of the challenge, the one where we have to use a format string attack.

Looking at source code, we see that client must enter user name, as in the previous example, which populates "username" variable, but in this case we do not find written password in the source, and there are not even any instructions to print the flag on the screen (there is a "print_flag" function, but inside it, the effective instruction useful to print the flag is commented, so it's not executed).

However, we note that flag variable exists, and contains a string, which is read from a file.
This variable is called "flag".

In the same function, there is also a "printf" instruction vulnerable to the format string attack, because this instruction outputs the content of the "username" variable without specifying the format.
Note: "username" variable is read from the user's keyboard by the "gets" function, and its content is printed to screen using a vulnerable "printf" (the vulnerability in this case is in the misused printf function)

The vulnerable statement is the following:
    printf(username)

The correct form, specifying the format should be something similar to this:
    printf("%s", username)

Since the printf statement is clearly vulnerable (because it does not specify the format), we can forge a text payload containing our evil format (based on "%p" specifier, or "%x" specifier), which ensures that in absence of the correct format and further arguments (which the function should be called with), these arguments are taken from the first locations on the stack near the stack pointer.

In this way we can read what is there in the stack, and by reading the last "n" memory locations (we mean, those above the stack pointer), with "n" more or less large, sooner or later we arrive at reading the memory location of the stack used to keep flag variable.

The text payload is built with the following python script, after analyzing the behavior of "print(username)" function, inside "print_flag" function, using the debugger, to see where "flag" variable is placed in the stack frame:

    payload="" 
    payload+="%p%p%p%p%p"
    payload+="%p%p--"
    payload+="%llx;" * 25

    with open("payload.txt", "w") as f:
        f.write(payload)

After executing this script to construct the payload, we send the payload to server:

`(cat payload.txt; echo) | nc flag-vault-v2.tryhackme.local 1337`

The server prints an output message, which, due to our format string attack, will contain the memory segment dedicated to the flag variable.

We copy and paste that segment into the following decoding script (in python), to decode the bytes into a string.\
<u>Note</u>: the following "flag_hex" memory segment is not the real segment running in the server (here, I printed my local test segment, to avoid spoilers)

    flag_hex = "a67616c66796d;7efdb0b8f964;7fffff73;7efdb0a34beb;234;0;7ffd83aaa9ad;7efdb0a278ca;7efdb0b905c0;7ffd83aaa921;b0b8f8e0;0;55e2bf99f050;7ffd83aaa920;7efdb0b8f8e0;55e2bf99f050;0;7efdb0bf3000;55e2bf99edd8;7efdb0a27b3e;1;7efdb0a318d2;1;7ffd83aaaab8;7ffd83aaa990"
    
    flag_hex_arr = flag_hex.split(";")
    flag_bytes = b""
    for v_str in flag_hex_arr:
        v_int = int(v_str, 16)
        flag_bytes += v_int.to_bytes(8, "little")
    
    print(flag_bytes.decode('utf-8', errors="ignore"))

Finally, we execute this script to decode memory addresses relative to "flag" variable into a readable string.
Well, the output string will contain the flag.
