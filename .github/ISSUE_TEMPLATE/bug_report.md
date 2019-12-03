---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

### Configuration  
impacket version:  
Python version:  
Target OS:  

### Debug Output With Command String  
i.e.  
smbexec -debug domain/user:password@127.0.0.1  
```
smbexec -debug domain/user:password@127.0.0.1
[+] StringBinding ncacn_np:127.0.0.1[\pipe\svcctl]
[+] Executing %COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>net group
[+] Executing %COMSPEC% /Q /c echo net group ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat
Traceback (most recent call last):
  File "/usr/lib64/python3.7/cmd.py", line 214, in onecmd
    func = getattr(self, 'do_' + cmd)
AttributeError: 'RemoteShell' object has no attribute 'do_net'
```

### PCAP  
If applicable, add a packet capture to help explain your problem.

### Additional context  
Space for additional context, investigative results, suspected issue.
