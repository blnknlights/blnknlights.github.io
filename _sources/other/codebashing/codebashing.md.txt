# Codebashing

## SQLi
```
A malicious user is able to manipulate the SQL statements that the server-side application sends to the backend database server for execution. 
```

## XXE - XML External Entity
```
A malicious user can attack poorly configured/implemented XML parser within an application. 
Malicious external entity references can be forced by an attacker, which results in unauthorized read-access to sensitive files on the server 
SAX - Simple API for XML - An event-driven online algorithm for parsing XML documents
```

## Command Injection
```
System command injection
Strictly validate any user-supplied input to the system command
```

## Session Fixation
```
The session token is controlled by the user and is not renewed at login time.
This means that an attacker can provide a url with a token he knows to a legitimate user. 
Once the user logs in, the now authenticated session will preserve that token, 
allowing an attacker to reuse the session token which is now authenticated. 
```

## Weak Session id Generator
```
Session id are generated with weak randomness.
Meaning they can be guessed or bruteforced.
```

## Reflected XSS
```
Attacker shares the url to the victim via external, means: Mail, chat, another forum post, documentation... anything 
The url has inline javascript in the case in the case of a GET, this javascript can do various things such as sending document.cookie to an attacker controlled domain:
http://1337H4x0r.tk/<script>alert(document.cookie)</script>

Mitigations: 
- HTTPOnly cookie flag:                 This flag prevents Javascript from accessing the cookie content, thus protecting it from being stolen if Reflected XSS is present.
- Content Security Policy HTTP Header:  This header restricts sources of all the page's content, including javascript code, to the whitelist of sources, thus making XSS exploitation harder to perform.
- X-XSS-Protection HTTP Header:         This header prevents browsers from loading a page if they detect Reflected XSS exploitation.
```

## Stored XSS (Persistent)
```
Javascript stored in the target website itself, for instance in a user profile details or in a blogpost, Anything that the website may serve back to other users 
```

## DOM Based XSS
```
You should recall that Stored XSS and Reflected XSS injections take place server-side rather than client-side. 
With DOM XSS, the attack is injected into the browser’s DOM thus adding complexity by making it very difficult to prevent and highly context specific 
(because an attacker can inject HTML, HTML Attributes, or CSS as well as URLs). 

As a general set of principles, the application should first HTML-encode and then JavaScript-encode any user-supplied data that is returned to the client. 
Due to the very broad attack surface, developers are strongly encouraged to review areas of code that are potentially susceptible to DOM XSS, including but not limited to:

window.name 
document.referrer 
document.URL 
document.documentURI 
location 
location.href 
location.search 
location.hash 
eval 
setTimeout 
setInterval 
document.write 
document.writeIn 
innerHTML 
outerHTML 
```

## Directory (Path) traversal
```
../../
Mitigation: 
Canonicalize file path e.g: os.path.realpath()
```

