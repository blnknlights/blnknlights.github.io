# Steganography

## file 
because of course.. 

## strings 
```bash
strings -n 6 file               # Extract the strings with min length of 6
strings -n 6 file | head -n 20  # Extract first 20 strings with min length of 6
strings -n 6 file | tail -n 20  # Extract last 20 strings with min length of 6
strings -e s -n 6 file          # Extract 7bit strings
strings -e S -n 6 file          # Extract 8bit strings
strings -e l -n 6 file          # Extract 16bit strings (little-endian)
strings -e b -n 6 file          # Extract 16bit strings (big-endian)
strings -e L -n 6 file          # Extract 32bit strings (little-endian)
strings -e B -n 6 file          # Extract 32bit strings (big-endian)
```

## cmp
```
# compare data at the byte level
cmp -v -b image1.jpg image2.jpg
```

## exiftool
```
exiftool -icc_Profile:all BU6iBcw.jpg # icc - international color consortium related fields only
exiftool BU6iBcw.jpg                  # all the fields
exiftool BU6iBcw.jpg                  # all the fields
exiftool -GreenTRC BU6iBcw.jpg -b|xxd # get the bytes for a specifi field
```

## foremost
```
foremost -i Queen.png
foremost Queen.png
```

## binwalk
```
binwalk Queen.png
binwalk -D=".*" Queen.png
binwalk -e Queen.png
```

## stegsolve
```
https://github.com/zardus/ctf-tools/blob/master/stegsolve/install 
java -jar -Xmx4g stegsolve.jar
(that's that tool that lets you quickly skim through the image layers and work on stereograms and all)
```

## stegosuite
```
will let you embed or extract data in image
```

## steghide
```
steghide info Queen.png
steghide embed -ef 'secret.txt' -cf 'fatbird.jpg'
steghide extract -sf 'fatbird.jpg' -xf secrets.txt
```

## stegcracker
```
bruteforce steghidden images (use stegseek instead)
```

## stegseek
```
replaces stegcracker apparently and it also a tool to bruteforce steghidden images 
Stegseek can also be used to detect and extract any unencrypted (meta) data from a steghide image

stegseek --seed slav.jpg
stegseek --crack slav.jpg /usr/share/wordlists/rockyou.txt
```

## zteg
```
https://github.com/zed-0xff/zsteg
detect stegano-hidden data in PNG & BMP
auto-runs a bunch of methods to extract things into a result folder
zsteg Queen.png > zsteg
```

## stegoveritas
```
works like zsteg in the sense that it does try a buch of methods automatically
not specific to PNG though
```

## convert (imagemagick)
```
convert blue_0.png -channel RGB -negate i_blue_0.png
convert i_blue_0.png -transparent white blue_0.png
convert half.png -threshold 90 90.png
```

## pngcheck
```
pngcheck -v Queen.png
```

## stegano
```
apparently a python lib for stego
I didn't really explore yet
pip install stegano
```

## fft stegpic
```
git clone https://github.com/0xcomposure/FFTStegPic.git
```

## stegpy
```

Embed data in an image using the LSB method (Least Significant Bit)
stegpy "done with stegpy" slav.jpg
stegpy _slav.png 
```

## pcrt

## cyberchef (web)
## asciitohex (web)
## stegonline (web)

## documentations
```
https://www.yeahhub.com/top-steganography-tools-ctf-challenges/
https://book.hacktricks.xyz/stego/stego-tricks
https://github.com/DominicBreuker/stego-toolkit
```
