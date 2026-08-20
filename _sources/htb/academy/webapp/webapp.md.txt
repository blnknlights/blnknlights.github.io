# Web Apps

## SQL injection
Obtaining Active Directory usernames and performing a password spraying attack against a VPN or email portal.

## File Inclusion 
Reading source code to find a hidden page or directory which exposes additional functionality that can be used to gain remote code execution.

## Unrestricted File Upload
Web application that allows a user to upload a profile picture that allows any file type to be uploaded (not just images). This can be leveraged to gain full control of the web application server by uploading malicious code.

## Indirect Object Reference (IDOR)
When combined with a flaw such as broken access control, this can often be used to access another user's files or functionality. An example would be editing your user profile browsing to a page such as /user/701/edit-profile. If we can change the 701 to 702, we may edit another user's profile!

## Broken Access Control
Another example is an application that allows a user to register a new account. If the account registration functionality is designed poorly, a user may perform privilege escalation when registering. Consider the POST request when registering a new user, which submits the data: username=bjones&password=Welcome1&email=bjones@inlanefreight.local&roleid=3. What if we can manipulate the roleid parameter and change it to 0 or 1. We have seen real-world applications where this was the case, and it was possible to quickly register an admin user and access many unintended features of the web application.



## URL ENCODING (common chr)

[https://www.w3schools.com/tags/ref_urlencode.ASP](https://www.w3schools.com/tags/ref_urlencode.ASP)  
```
space   %20    +
.       %2E
,       %2C 
-       %2D 
<       %3C
=       %3D
^       %5E 
:       %3A
;       %3B
!       %21
"       %22
#       %23
$       %24
%       %25
&       %26
'       %27
(       %28
)       %29
/       %2F
@       %40
```

## HTML entities
```
     &nbsp;    &#160;
<    &lt;      &#60;
>    &gt;      &#62;
&    &amp;     &#38;
"    &quot;    &#34;
'    &apos;    &#39;
¢    &cent;    &#162;
£    &pound;   &#163;
¥    &yen;     &#165;
€    &euro;    &#8364;
©    &copy;    &#169;
®    &reg;     &#174;
```


## DOM     
The W3C Document Object Model is a platform and language-neutral interface that allows programs and 
scripts to dynamically access and update the content, structure, and style of a document.

```
Core DOM - the standard model for all document types
XML DOM  - the standard model for XML documents
HTML DOM - the standard model for HTML documents
```
