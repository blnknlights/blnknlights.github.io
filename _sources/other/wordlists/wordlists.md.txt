# Making Custom Wordlists

## Crunch
Crunch can create wordlists based on parameters such as words of a specific length, a limited character set, or a certain pattern. It can generate both permutations and combinations
```
-t <pattern> 
-o <output file>
-d limit the ammount of dup chr ex = 2@ limits the lower case alphabet to output like aab and aac not aaa
```
```
@  lower case chr
,  upper case chr
%  int
^  symbols
```
```bash
crunch <minimum length> <maximum length> <charset> -t <pattern> -o <output file>
crunch 4 8 -o wordlist   # generate a wordlist of 4 to 8 characters, using the default character set
crunch 17 17 -t ILFREIGHT201%@@@@ -o wordlist    #generate a wordlist 17 characters, ILFREIGHT201[0..9]<uid>
crunch 12 12 -t 10031998@@@@ -d 1 -o wordlist
crunch 8 8 + + 12345 -t apple@1% -l aaaaa@aa
```


## CUPP
Common User Password Profiler

Used to create highly targeted and customized wordlists based on information gained from social engineering and OSINT. 
People tend to use personal information while creating passwords, such as phone numbers, pet names, birth dates, etc.
```
-i interactive 
-l load wordlists from repo
```

## Kwprocessor
Keyboard walks processor

Tool that creates wordlists from keyboard walks logics
```
-s  shift - include chr reachable by holding shift
```
```bash
./kwp [options]... basechars-file keymap-file routes-file
./kwp -s 1 basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route
```
       
## Prince processor
PRobability INfinite Chained Elements

[https://github.com/hashcat/princeprocessor.git](https://github.com/hashcat/princeprocessor.git)  
Generates passwords using the PRINCE algorithm.  
The program takes in a wordlist and creates chains of words taken from this wordlist. 
```
--keyspace          - find the number of combinations produced from the input wordlist
--pw-min=NUM        - change min pass length
--pw-max=NUM        - default is 16 chr
--elem-cnt-min=NUM  - Minimum number of elements per chain
--elem-cnt-max=NUM  - Maximum number of elements per chain
```
```bash
./pp64.bin -h
./pp64.bin --keyspace < words                               # find the number of combinations produced from the input wordlist
./pp64.bin -o wordlist.txt < words                          # output a worldlist based on words
./pp64.bin --pw-min=10 --pw-max=25 -o wordlist.txt < words  # output a worldlist based on words with a min size of 10 and max size 25
./pp64.bin --elem-cnt-min=3 -o wordlist.txt < words         # The command above will output words with three elements or more, i.e.," dogdogdog`."
```

## CeWL
Spiders and scrapes a website and creates a list of the words that are present. 
This kind of wordlist is effective, as people tend to use passwords associated with the content they write or operate on
CeWL also supports the extraction of emails from websites.
It's helpful to get this information when phishing, password spraying, or brute-forcing passwords later.
```
-d <depth to spider> 
-m <minimum word length> 
-w <output wordlist>
-e extract emails
```
```bash
cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url of website>
cewl -d 5 -m 6 -e http://inlanefreight.com/blog -w wordlist.txt
```

## Hashcat-utils
The Hashcat-utils repo contains many utilities that can be useful for more advanced password cracking. 
The tool maskprocessor, for example, can be used to create wordlists using a given mask. 
Detailed usage for this tool can be found here: -> [https://hashcat.net/wiki/doku.php?id=maskprocessor](https://hashcat.net/wiki/doku.php?id=maskprocessor)  

Hashcat.potfile
```bash
-d: -f 2- ~/hashcat.potfile
hcat --show
```
 
## Bopscrk
```bash
./bopscrk.py -m 8 -M 10 -c -l -w apple
./bopscrk.py -i
```

