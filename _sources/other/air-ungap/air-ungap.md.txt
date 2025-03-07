# Air-Ungap


## Create networks

Create an air-gapped network and one with internet access
```bash
docker network create --internal --subnet 10.10.10.0/24 internal
docker network create internet
```

## Create the containers and connect them

Create a fedora container and connect it to the internal network only
```bash
docker run -d --network internal --name fedora fedora tail -f /dev/null
```

Create the proxy container and connect it to the internal network
```bash
docker run --name squid-proxy --network=internal -d --rm -p3128:3128 ubuntu/squid
```

But also give it access to the internet
```bash
docker network connect internet squid-proxy
```

You can double check your config this way
```bash
docker inspect squid-proxy -f '{{json .NetworkSettings.Networks }}'|jq .
```

```bash
docker inspect fedora -f '{{json .NetworkSettings.Networks }}'|jq .
```

## Try to connect to internal and external resources

From the fedora container, we should be able to access only internal resources
```bash
docker exec -it fedora /bin/bash
```

We expect requests to external resources to fail
```bash
curl http://example.com
^C
```

But we should be able to reach out to resources on the internal network, so the proxy in this case.
```bash
curl -sI http://10.10.10.3:3128|grep Serv
Server: squid/5.7
```

## Reach out to the internet through the proxy 

Even though we cannot reach out directy as demonstrated before
```bash
curl https://example.com
^C
```

We can reach out through the proxy
```bash
curl -sI -x http://10.10.10.3:3128 http://example.com|grep Serv
Server: ECS (nyb/1D04)
```

## Tail the proxy access log
From the proxy container, tail the access logs, so you can observe traffic going through the proxy
```bash
docker exec -it squid-proxy /bin/bash
```
```bash
tail -f /var/log/squid/access.log
```

## Use the proxy to reach the dnf repos

```bash
dnf repolist
```

Since this system is air-gapped it can reach to the dnf repos to upgrade itself
```bash
dnf update
```
(the above command will fail)

But we can funnel the traffic for the dnf repos through the proxy now. All we've got to do is set a proxy for each entries in the repolists.
```bash
cd /etc/yum.repos.d/
ls -la
total 36
drwxr-xr-x 2 root root 4096 Sep 14 06:49 .
drwxr-xr-x 1 root root 4096 Sep 17 10:34 ..
-rw-r--r-- 1 root root  728 Apr  6 00:00 fedora-cisco-openh264.repo
-rw-r--r-- 1 root root 1302 Apr  6 00:00 fedora-modular.repo
-rw-r--r-- 1 root root 1349 Apr  6 00:00 fedora-updates-modular.repo
-rw-r--r-- 1 root root 1391 Apr  6 00:00 fedora-updates-testing-modular.repo
-rw-r--r-- 1 root root 1344 Apr  6 00:00 fedora-updates-testing.repo
-rw-r--r-- 1 root root 1286 Apr  6 00:00 fedora-updates.repo
-rw-r--r-- 1 root root 1239 Apr  6 00:00 fedora.repo
```

Add an empty new line at the end of all repo files
```bash
for i in $(ls -1);do printf '\n' >> $i;done
```

Replace all empty new lines with the proxy address, + a newline
```bash
sed -i 's/^$/proxy\=http\:\/\/10.10.10.3:3128\n/g' ./*
```

So we are now effectively pointing all repos through our proxy, which means we can now upgrade our system, even though it is (was) air-gapped.
```bash
dnf update
Fedora 38 - aarch64                                                    17 MB/s |  79 MB     00:04
Fedora 38 openh264 (From Cisco) - aarch64                             1.8 kB/s | 2.5 kB     00:01
Fedora Modular 38 - aarch64                                           2.0 MB/s | 2.7 MB     00:01
Fedora 38 - aarch64 - Updates                                          17 MB/s |  31 MB     00:01
Fedora Modular 38 - aarch64 - Updates                                 1.3 MB/s | 2.1 MB     00:01
Dependencies resolved.
======================================================================================================
 Package               Architecture          Version                      Repository             Size
======================================================================================================
Upgrading:
 curl                  aarch64               8.0.1-4.fc38                 updates               345 k
 libcurl               aarch64               8.0.1-4.fc38                 updates               305 k

Transaction Summary
======================================================================================================
Upgrade  2 Packages

Total download size: 650 k
Is this ok [y/N]:
```

And we still can't reach out to the internet without a proxy.
```bash
curl http://example.com
^C
```
