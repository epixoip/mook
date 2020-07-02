/*
 Copyright (c) 2012, Tom Steele & Jeremi Gosney
 all rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met: 
 
 1. Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer. 
 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution. 
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
*/

#include <iostream>
#include <string>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include "iface.h"

iface getIface(std::string interface_string)
{
    int j;
    struct sockaddr_in *s4;
    static struct iface iface;
    struct ifaddrs *myaddrs, *ifa;
    static char buf[16];
    
    if (getifaddrs(&myaddrs))
        std::cerr << "getifaddrs\n";
    
    for (ifa = myaddrs, j=0; (ifa != NULL && j < 8); ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        if ((ifa->ifa_flags & IFF_UP) == 0)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET) 
        {
            
            s4 = (struct sockaddr_in *)(ifa->ifa_addr);
            if (inet_ntop(AF_INET, (void *)&(s4->sin_addr), 
                          buf, INET_ADDRSTRLEN) != NULL) 
            {
                j++;
                // if user did not specify an interface
                if (interface_string.empty()) 
                {
                    if (j==2) {
                        iface.name = ifa->ifa_name;
                        iface.ip = buf;
                        return iface;
                    }
                }
                
                // if user did specify interface
                std::string tempiface = ifa->ifa_name;
                if (interface_string == tempiface) 
                {
                    iface.name = interface_string;
                    iface.ip = buf;
                    return iface;
                }
                
            }
        }
    }
    
    freeifaddrs(ifa);
    // exit if not found
    std::cerr << "unable to get interface and src ip address!\n";
    exit(1);
    
}
