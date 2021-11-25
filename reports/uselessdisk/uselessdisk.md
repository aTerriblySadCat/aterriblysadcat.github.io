# UselessDisk
## The name says it all.

Written by Martijn van den Berk.
Published on the 25th of November, 2021.

## Introduction
UselessDisk, a piece of malware found running in the Any.Run sandbox. Its victim? A 32-bit Windows 7 system. Identified by its behavior as a piece of ransomware and a locker, it was a prime target for practicing malware analysis given the prevalence of ransomware in today’s environment.

However, as research into the malware progressed it turned out that UselessDisk really does do its name justice. What seemed on the surface to be a nasty piece of ransomware was nothing more than a sheep in wolf’s clothing. Talking the talk, but not walking the walk.

In short, it doesn’t encrypt any files at all. It just overwrites the system’s boot sector with its own malicious boot record which it then boots into on reboot and subsequent boots. More boots here than in a Dr. Martens factory.

## Contents
1. Introduction
2. Indicators of compromise
    1. YARA rule
    2. EXE hashes
    3. Sector hashes
    4. Debug hashes
    5. Loaded Libraries
    6. Timestamps
3. Mitigation & remediation
    1. Better prevented than cured!
    2. In case of concern
    3. The cure
4. Malware summary - A wolf lacking teeth
5. Malware deep dive - The little engine that couldn't
    1. The money function
    2. FUN_004012e0
    3. CreateFileA
    4. DeviceIoControl
    5. WriteFile
    6. CloseHandle
    7. WinExec
6. Conclusion
    1. Pitroxin.A
    2. The analysis process
