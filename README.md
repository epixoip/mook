Mook
======
##Intro##
Mook is a tool used to scan for available services through a filtering device
that uses some for of syn-flood protection. These devices will reply with a 
SYN/ACK to every SYN packet sent. Making it impossible for traditional port
scanners to detect legitimate services. 

For install instructions see INSTALL.txt

##Scan Types##
There are two types of scans Mook can use to detect an available service

1. Connect Scan: Using the kernel to handle the connection we attempt to establish
a 3-way handshake with the target, we then close the socket which will send a
FIN/ACK. A pcap listener is started, most ports will send a combination of
a ACK, PSH/ACK, or FIN/ACK. If either of these packets is received the confidence
score will be raised by one and the port will be flagged as open.

2. MSS Option Scan: If the filtering device has been configured in a certain
way, sometimes legitimate ports are allowed in before the syn-flood protection
can take place. Sometimes the MSS TCP option size will be different on the open 
ports and the closed ports. If this is the case you can use "-m <size>" and 
essentially perform a SYN scan. If the SYN/ACK's MSS size received from the target
is the same as the specified size, the port will be flagged as open. Most of the 
time you'll want to set this to '1460' as that is most common. 

##Sample Usage##
Standard connect scan: 
```
    ./mook -p 1-1024 -t 150 192.168.1.1
```
MSS Option Scan: 
```
    ./mook -m 1460 -n -p 1-1024 -t 150 192.168.1.1
```
Both: 
``` 
    ./mook -m 1460 -p 1-1024 -t 150 192.168.1.1
```

In addition to the scan types above, use the '-c' and '-r' options when you 
initially discover a syn-proxying gateway. One situation where these come in handy
is where you encounter a device that behaves differently than the standard.
For instance, a F5 BIG-IP will send an additional ACK once the 3-way handshake has
been completed. This can be taken care of by simply specify a minimum confidence
of 2 i.e.: '-c 2'
Detailed Scan: 
```
    ./mook -p 1-1024 -c 2 -r -t 150 192.168.1.1
```

##TCP Flag Details##
####Typical SYN Scan#####
```
Open Port

    client ---- syn -------> server
    client <--- syn/ack ---- server

Closed Port

    client ---- syn -------> server
    client <----rst -------  server

Filtered Port

    client ---- syn -------> server
    *no reply
```
####SYN scan through a gateway with syn-flood protections####
```
Open Port

     client ---- syn -------> server
     client <--- syn/ack ---- gateway

Closed Port

    client ---- syn -------> server
    client <--- syn/ack----  gateway

Filtered Port

    client ---- syn -------> server
    client <--- syn/ack ---- gateway
``
####Mook Connect Scan####
#####3-way handshake#####
```
    client ---- syn -------- server   
    client <--- syn/ack ---- server         
    client ---- ack -------- server 
```
#####client closes connection#####
```
    client ---- fin/ack ---- server
```
#####Either one of these flags will raise the "confidence" level of the port and flag it as open#####
```
    client <--- ack ------- server         
    client <--- psh/ack --- server    
    client <--- fin/ack --- server
```
