---
layout: post
title: TryHackMe - "Billing"
categories: Challenges
tags: red-team attack 
---
In this challenge we see how a known vulnerability of a server-side web application, together with an incorrect configuration of the usage privileges of a "root" application, allows to take total control of the target system.

The web application in question is "MagnusBilling", version 6.0. 
We can find out this information simply by exploring it with the browser (better if in developer mode).

This version of the application is vulnerable to an RCE attack.
The vulnerability identifier is the following: CVE-2023-30258

## Exploit

Using the Metasploit framework, we can exploit this remote command execution vulnerability, injecting a remote Meterpreter shell that allows us to execute several commands with privileges of the user associated to the web application.

`meterpreter> getuid`

The result is "asterisk" (the user associated to magnusbilling framework).
With this privileges we can read the user flag contained in "magnus" home folder. This flag has Linux permissions mode "644", so we can read it

`⁠meterpreter> cat /home/magnus/user.txt`

Obviously we cannot read the "root" flag, as we do not have its super privileges.

## Privilege escalation

If we call `⁠sudo -l`, to see which root commands we can use as a limited current user, we see that the "fail2ban-client" application is present. This executable is useful for managing the "fail2ban" service. 
Fail2ban is a software that continuously checks the log files related to the authentication requests that clients make to our servers (http, ssh), and when it notices repeated anomalies, such as repeated failed login attempts from a certain client, it adds a blocking rule in the iptables firewall for the potentially malicious IP address.

In this challenge machine, "fail2ban" is active: it monitors web access attempts to "MagnusBilling" application and ssh attempts to "sshd" server, in order to block any clients that are trying to access using brute force attacks.

Now, the interesting thing is that, using "fail2ban-client" command, we can reconfigure the service, replacing the default blocking rule with our own evil command: we can create a SUID root shell (yes, root shell, because fail2ban runs with root permissions).

    sudo fail2ban-client restart
    sudo fail2ban-client unban --all
    sudo fail2ban-client set "sshd" action "iptables-multiport" actionban "cp /bin/bash /tmp/shell && chmod 4755 /tmp/shell"

With the last instruction shown here, we are telling the "fail2ban" service to modify the blocking rule of clients that are trying to access the sshd server, replacing it with the new command just reported (which creates a malicious shell)

Well, now from our attacker machine (which would act as an ssh "client") we can simulate a brute force attack (simply making repeated ssh login requests, inserting random wrong passwords), in order to trigger the fail2ban rule just configured in the server machine.

Let's do this, and we will obtain the creation of our SUID root shell in the temporary directory of the target machine.

Now all that remains is to execute the following commands in the target machine, to open the shell and read the flag of the "root" user, contained in its home folder.

`⁠/tmp/shell -p`
`⁠cat /root/root.txt`

The challenge is over!