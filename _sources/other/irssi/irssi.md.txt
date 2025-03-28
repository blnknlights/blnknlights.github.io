# Irssi

## Launch
Once IRSSI is installed and launched, you need to connect to an IRC network    
```
/network           # lists available IRC Networks
/clear             # Clears the screen
/connect freenode  # Connect to thefreenode Network
```
    
Then you need to pick a NickName, you can pick any nickname and stetup a channel where people can join you:
```
/nick Sup0s1tW4r   # choose the nick SupOs1tW4r
/join superchannel # create and join the channel "superchannel"
```

## Window navigation
Everytime you do someting IRSSI opens a new window in the background 
```
/window 1        # Move to window 1
/window 2        # Move to window 2
/window 3        # Move to window 3
/window close         # Close the current window
^P - Previous window  # Move to the previous window
^N - Previous window  # Move to the next window
```

## Nickserv
Intersting channels will probably have a few requirements, or need an invite.  
But at the very least you'll need to be identified, making sure that you're the actual owner of your nickname 
```
/msg NickServ register .......1337Pa$$w0rd.......... youremail@example.com
```
Register the user 'Supos1tw4r' to youremail@example.com  
This works because you already mentionned that the nick you want is Sup0s1tW4r  
Note that this will open a new window, since you are now talking to the NickServ service   
That window is opened in the background, so it is responding to you, but in another window  
Check the Window section to understand how to navigate windows  
```
/msg NickServ verify register Sup0s1tW4r TheKeyalksjfa;lj
```
Now use the verification key that you received by email (IRC is not case sensitive as far as I can tell)
```
/msg NickServ identify .......1337Pa$$w0rd..........
```
And finaly identify yourself to nicserv with your password
```
/msg NickServ status
```
Verify that you're actually identified (again you need to be in the right window)
```
note, once you have a registered nick you can and should be setting up your config file to login to it automatically
```
            
## Search channels:
```
/help list
/list
/list #bar*
/list *bar*
ist #linux* -min=30
```

## Search freenode channels:
```
/msg alis help
/msg alis help list
/msg alis list #bar*
/msg alis list *bar*
/msg alis list #linux* -min=30 # Search for a channel including the word linux of min 30 users
```
    
## Channel commands
```
/msg #NickName
/msg #Service
/join #channel 
/leave #channel
/list
/channel
/part #channel
/clear
/quit
/name
```

## vHost
```
/join #vhost
!vhost blnkn@phyllium.sp
!groupvhost blnkn@phyllium.sp
```

```
/scrollback goto -100
```

