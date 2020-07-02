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
#include <vector>
#include <algorithm>
#include <functional>
#include <string>
#include <sstream>
#include <stdlib.h>
#include "ports.h"

void croak();

// takes string like 1-80, 1,2,3,4 or just 80 and returns
// a vector<int> of ports to be scanned
std::vector<int> explodePorts(std::string &port_string)
{
    std::vector<int> ports;
    
    // split the string by '-' once
    if (port_string.find('-') != std::string::npos) {
        size_t first = port_string.find('-');
        size_t last = port_string.find('-', first+1);
        if (last != std::string::npos)
            croak();
        std::string start = port_string.substr(0,5);
        std::string end = port_string.substr(first+1);
        
        int start_i;
        int end_i;
        std::istringstream start_s(start);
        if (!(start_s >> start_i))
            croak();
        std::istringstream end_s(end);
        if (!(end_s >> end_i))
            croak();
        
        if (end_i < start_i)
            croak();
        
        if (start_i < 1 || end_i > 65535)
            croak();
        
        while (start_i <= end_i)
        {
            ports.push_back(start_i);
            start_i++;
        }
        
    }
    
    // split the string by ',' and add to ports
    else if (port_string.find(',') != std::string::npos) {
        size_t counter_c = 0;
        size_t counter_p = 0;
        
        while(counter_c != std::string::npos)
        {
            counter_c = port_string.find(',', counter_c+1);
            std::string port = port_string.substr(counter_p, counter_c);
            counter_p = counter_c + 1;
            int a_port = 0;
            std::istringstream convert(port);
            if (!(convert >> a_port))
                croak();
            if (a_port > 65535 || a_port < 1)
                croak();
            ports.push_back(a_port);
        }
    }
    
    // port_string is probably just a single port
    else if (port_string.length() < 6) {
        std::istringstream convert(port_string);
        int a_port = 0;
        if (!(convert >> a_port))
            croak();
        if (a_port > 65535 || a_port < 1)
            croak();
        ports.push_back(a_port);
    }
    else {
        croak();
    }
    
    // shuffle and unique the vector, then return it
    std::random_shuffle(ports.begin(), ports.end());
    std::vector<int>::iterator uq = std::unique(ports.begin(), ports.end());
    ports.erase(uq, ports.end());
    return ports;
}

// print and die
void croak()
{
    std::cerr << "Invalid port specification!\n";
    exit(1);
}
