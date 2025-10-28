# YARA Verificator Writeup

## Idea

## what is winapi? 

### wininet?
WinINet API is one of the APIs under the Networking and Internet categories in the WinAPI.

Let's look at the instructions of the challenge again: `the malware disguised itself as a legitimate browser by mimicking common web traffic patterns`. This should indicate something. One of the hints linked to WinINet documentation. 

Basically, `InternetOpen` establishes the Internet connection to the client application. 
