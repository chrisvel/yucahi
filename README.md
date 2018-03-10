# yucahi

```
db    db db    db  .o88b.  .d8b.  db   db d888888b v0.1
`8b  d8' 88    88 d8P  Y8 d8' `8b 88   88   `88'   
 `8bd8'  88    88 8P      88ooo88 88ooo88    88    
   88    88    88 8b      88~~~88 88~~~88    88    
   88    88b  d88 Y8b  d8 88   88 88   88   .88.   
   YP    ~Y8888P'  `Y88P' YP   YP YP   YP Y888888P
```

`yucahi` is a WiFi scanner that shows probes and beacons around.

__The main goal is to show the networks the device has previously connected and as a result reveal the history of the places the user has connected and been to.__

It shows the MAC address, vendor of network interface card, ESSID and calculates estimated distance with channel modulation and signal power. Interface turns to mode monitor automatically.

yucahi also organizes, uses colored output and sorts probes by time passed since last seen device.

It also offers a channel hopper that you can control (in seconds).

Finally, the information gathered is exported in JSON format for importing it with any front-end framework and displaying it in real time on an html page or adding it to any log aggregator (e.g. fluentd, logstash etc.)

### Current status

_* In development_

My biggest goal is to make it in a future Kali Linux release as a Wifi Pentesting standard tool.

### Roadmap

- [TODO]: Make installation easier
- [TODO]: Replace repeating code
- [TODO]: Add tests

### Dependencies
- python 2.7
- scapy
- a compatible wifi adapter already recognized by the O/S
- sudo priviledges

### Installation
- `pip2 install -r requirements.txt` or `pip` If you only have python 2.7 installed.

### How to run
`yucahi` can scan networks with CIDR or single IP Addresses:

`sudo python2 yucahi.py wlp0s20u1`

### Screenshots

![Screenshot Running Command](/screenshots/yucahi_1.png?raw=true "ss1")

### License

Copyright (c) 2018 Chris Veleris

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
