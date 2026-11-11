---
layout: post
title: TryHackMe - "Lookup"
categories: Challenges
tags: pen-testing 
---
[Link to the challenge](https://tryhackme.com/room/lookup)

## Enumeration

On the target machine, as usual, the web server is running. With our browser, or with "wget" command, we try to connect to the index page and see what happens.
The web server responds with a 302 redirection to the virtual host "lookup.thm"

We add this virtual host in our /etc/hosts file, to resolve it to the ip address of the target machine.

Now, using our browser, we can correctly connect to the virtual host "lookup.thm"

A login form appears.
The behavior of the form is the following:
- if the user writes both the username and password incorrectly, then the system returns the message "Wrong username and password..."
- if the user enters a valid username, but the password is incorrect, the system returns "Wrong password..."

We can rely on this behavior to enumerate users (we use a dictionary of names)

`hydra -u -L names.txt -p "wrongpass" lookup.thm -s 80 http-post-form "/login.php:username=^USER^&password=^PASS^:F=Wrong username or password"`

Well, users found: admin, jose

Now that we know at least two usernames, let's try to find their passwords.
We already anticipate that the really useful user is not "admin", but "jose".

Let's do a brute force attack (again using hydra), to find the password of the web user "jose"

`hydra -l jose -P /usr/share/wordlists/rockyou.txt lookup.thm -s 80 http-post-form "/login.php:username=^USER^&password=^PASS^:F=Wrong password"`

Password found. It's "............" (we don't give spoilers) 😊

Now we can log in as user "jose" in the web lookup application.
We are redirected once again to a new virtual host, "files.lookup.thm".
This is a web file manager, containing several text files that seem useful, but are not really.

Using the browser inspector we find that the file manager version is "elFinder 2.1.47", which is vulnerable to CVE⁠-2019-9194 (vulnerability that allows uploading a jpg file with a "malicious" name, allowing remote command execution, such as creating a web shell, for example).

## Exploitation

In Metasploit framework there is the exploit related to this vulnerability just discussed, so we set it up and use it in order to obtain a Meterpreter reverse-shell, which will have limited web-server privileges (user "www-data").

In the target machine there is a limited user called "think", and then of course the usual "root", who are the owners of the text flags that we are looking for to solve the challenge.
We want to get the "think" privileges, but, what is his password? In his home directory there is flag.txt, and there is also a private password file (".passwords.txt"), but we can't open them, because as a very limited user "www-data", do not have permissions to read them.

We must escalate privileges.

## Privilege escalation

Using the newly created Meterpreter shell, we load the "linpeas.sh" script on the target machine, which allows us to check locally (on the victim machine) for the existence of various vulnerabilities, which allow us to escalate privileges.

The Linpeas output shows us a root SUID executable file, named "pwm" that calls the "id" command to figure out who the current user is and then reads ".passwords.txt" file in his home directory.

This SUID command (pwn) seems harmless at first glance, and may seem unexploitable, but it is actually dangerous: we can create our own fake "id" command in the /tmp directory, put this directory at the beginning of the PATH environment variable, so that the /tmp directory is given priority in the search for command executables that are invoked by us, or by some other program.

This is how we fool the pwm program: when we run the pwm program, it will call our fake "id" command (which will not return the current user "www-data", but will return the user we want, named "think", so that we can read his private password file)

Our fake "id":

    #!/bin/bash 
    
    echo "uid=1000(think) gid=1000(think) groups=1000(think),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio)"

Then:

`⁠export PATH=/tmp:$PATH`

Then, we call "pwm", and then the file named ".passwords.txt", owned by "think" user, will be read!!
This file contains "think" password (we don't give any spoiler) 😊
Now, with command "su - think" we can become "think", and therefore read the first flag.

As for the second flag (the one owned by "root"), it's all easy: "think" user has sudo permissions to execute "look" command (you can check it with "sudo -l")

We execute the following command:

`sudo look "" /root/root.txt`

...and here is the final flag!

