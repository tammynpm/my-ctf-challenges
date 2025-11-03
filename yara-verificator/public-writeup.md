# YARA Verificator Writeup

![](src/description.png)

## Background
Digital forensics in CTFs is not just disk analyzing. There are also memory forensics, network forensics, steganography (though not practically used anymore), file analysis, etc. I want to introduce a different type of digital forensics in this CTF.

This is threat detection forensics challenge. In real investigations, analysts use YARA to triage large file sets for malware indicators. This challenge will mirror a forensics triage process.  

![](src/renamed.png)

The distributed [source code](src/chall.c) for this challenge.  

> The executables generated from this code cannot do anything to your computer because it will immediately be flagged by Windows Security (WS). WS uses antivirus software (AV software) like Microsoft Defender Antivirus to scan files and look for malware signatures and suspicious behaviour.  

## Challenge Summary
In this challenge, we are provided with a set of over 400 executables and dll files. We are asked to write a YARA rule that could detect the malicious files that attacker had implanted. 

There are two sets of data originally that got mixed into one. One set includes all benign .exe (executable) and .dll (Dynamic Link Library) files from `C:\Windows\SYSTEM32`. The other set contains all the "malicious-wannabe" executable files that the source code above generated with a bit of variations for each one just to not duplicate them. 

## solution
```shell
rule http_c2_agent_sample
{
    strings:
        $user_agent = "Mozilla/5.0"
		$create_process = "CreateProcess"
        $wininet1 = "InternetOpen"
    condition:
        all of them
}
```
### YARA
YARA (Yet Another Recursive Acronym) must be one of the most flexible tools in Threat Detection. It has a really simple structure, and is highly customizable. 

For example: 

```
rule detection{
	strings:
		$pattern1="hello"
		$pattern2="world"
	conditions:
		any of them
}
```
Here are more examples of [YARA rules used to detect some well-known malware](https://github.com/reversinglabs/reversinglabs-yara-rules/tree/develop/yara).

We need to identify behavioral rules from the given description. Let's look at the instructions of the challenge again: `the malware disguised itself as a legitimate browser by mimicking common web traffic patterns`. This suggest the sample uses `InternetOpen` or similar functions in `wininet` for web requests as one of the hints linked to WinINet documentation. 

`All infected Windows machines are using the same User-Agent string: Mozilla/5.0` resembles the real User-Agent string. 

Translate these behaviors to YARA string matches where each string targets a key characteristic of the malware:

Using `all of them` condition ensures the rule only matches samples that contain all three behaviors, reducing false positives. If we only want to detect partial matches, we could use `any of them` instead. 
 
Once your rule is written, test it against the sample. If it doesn't trigger the correct files, adjust string matches until they matches. 

[CreateProcess()](https://medium.com/@theCTIGuy/windows-api-highlight-createprocess-ec1ec0915b9c)

CreateProcess() is one of the most used WinAPI functions. Many processes running in your computer's background have probably been created by this function. Malware samples use CreateProcess() to execute payloads or commands received from a C2 server.

[InternetOpen()](https://www.aldeid.com/wiki/InternetOpen) 
One of the parameters to `InternetOpen` is the `User-Agent` which is a good signature to it. 

Basically, how to write the detection rules for the correct samples are just to stick to what we are given and have observed so far, i.e. the descriptions. 

By combining the indicators above (the use of WinINet, the Mozilla/5.0 user-agent, and process creation behivor), the YARA rule can effectively identify all malicious samples while avoiding false positives. 

## result
![](src/image2.png)

The flag is **MINUTEMAN{w3_ju57_l0v3_y37_4n07h3r_r1d1cul0u5_rul3_0300393325}**


## Author's Note

One team has the solve for this by using the `strings` command. 
I noticed that compiling in Debug mode left behind the PDB file paths, which allowed players to shortcut the intended solution using `strings`.  

For example, when apply the `strings` command on one of the "malicious" file `variant-0.exe`, you can see `C:\Users\thkpd\source\repos\http-c2-agent\x64\Debug\http-c2-agent.pdb`, the PDB path (Program Database path), which contain debugging info that links compiled code back to source code.

Future versions would use Release builds to avoid this. 


