# Hash Muncher

*Grab NetNTLMv2 hashes using ETW with administrative rights on Windows*

[![GitHub all releases](https://img.shields.io/github/downloads/lkarlslund/hashmuncher/total)](https://github.com/lkarlslund/hashmuncher/releases) ![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/lkarlslund/hashmuncher/prerelease.yml?branch=main)

- Uses Event Tracing for Windows (ETW) to get access to raw packet data for SMB authentication packets
- Decodes NTLM message types 2 and 3
- Outputs to stdout
- Press Ctrl-C to stop processing
- Crack hashes with HashCat using -m 5600

### Download auto built binaries from [releases](https://github.com/lkarlslund/hashmuncher/releases) or build and install on Windows with this Go command

```bash
go install github.com/lkarlslund/hashmuncher@latest
```

### Cross compile the Windows binaries on any Golang supported platforms with PowerShell installed

```powershell
git clone https://github.com/lkarlslund/hashmuncher
cd hashmuncher
./build.ps1
```

### Usage

```bash
hashmuncher.exe
```

Now wait for someone to authenticate against your machine. There are various techniques for this but SCF and LNK files with icons pointing to your machine is a popular way. Press Ctrl-C when you're done, copy output to a text file and run HashCat.

## Detection

- No idea, please leave feedback

## Mitigation

- None for the ETW part, this is part of the Windows design says Microsoft
- Disable NTLM entirely! It probably won't be painless - but see [Farewell NTLM - It is time to disable NTLM](https://www.scip.ch/en/?labs.20210909)

## History

I've been playing with ETW on and off, but once I saw the very cool [research from Nettitude Labs](https://labs.nettitude.com/blog/etwhash-he-who-listens-shall-receive/) I knew I had to make this into an easy to use tool in my favourite language Golang! Nettitude Labs has a working [POC](https://github.com/nettitude/ETWHash) written in C# running under the .Net framework, and might be a better option for you. So I'm not really inventing anything here, just adding this as an alternative.

If you like Windows security stuff you might also like my attack graph tool [Adalanche](https://github.com/lkarlslund/Adalanche)
