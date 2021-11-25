# UselessDisk
## The name says it all.

Written by Martijn van den Berk.

Published on the 25th of November, 2021.

## 1. Introduction
UselessDisk, a piece of malware found running in the Any.Run sandbox. Its victim? A 32-bit Windows 7 system. Identified by its behavior as a piece of ransomware and a locker, it was a prime target for practicing malware analysis given the prevalence of ransomware in today’s environment.

However, as research into the malware progressed it turned out that UselessDisk really does do its name justice. What seemed on the surface to be a nasty piece of ransomware was nothing more than a sheep in wolf’s clothing. Talking the talk, but not walking the walk.

In short, it doesn’t encrypt any files at all. It just overwrites the system’s boot sector with its own malicious boot record which it then boots into on reboot and subsequent boots. More boots here than in a Dr. Martens factory.

## Contents

<dl>
<dt>1. Introduction</dt>
<dt>2. Indicators of compromise</dt>
<dd>2.1. YARA rule</dd>
<dd>2.2. EXE hashes</dd>
<dd>2.3. Sector hashes</dd>
<dd>2.4. Debug hashes</dd>
<dd>2.5. Loaded Libraries</dd>
<dd>2.6. Timestamps</dd>
<dt>3. Mitigation & remediation</dt>
<dd>3.1. Better prevented than cured!</dd>
<dd>3.2. In case of concern</dd>
<dd>3.3. The cure</dd>
<dt>4. Malware summary - A wolf lacking teeth</dt>
<dt>5. Malware deep dive - The little engine that couldn't</dt>
<dd>5.1. The money function</dd>
<dd>5.2. FUN_004012e0</dd>
<dd>5.3. CreateFileA</dd>
<dd>5.4. DeviceIoControl</dd>
<dd>5.5. WriteFile</dd>
<dd>5.6. CloseHandle</dd>
<dd>5.7. WinExec</dd>
<dt>6. Conclusion</dt>
<dd>6.1. Pitroxin.A</dd>
<dd>6.2. The analysis process</dd>
</dl>

## 2. Indicators of compromise

### 2.1. YARA rule

### 2.2. EXE hashes

### 2.3. Sector hashes

### 2.4. Debug hashes

### 2.5. Loaded libraries

### 2.6. Timestamps

## 3. Mitigation & remediation

### 3.1. Better prevented than cured!

### 3.2. In case of concern

### 3.3. The cure

## 4. Malware summary - A walk lacking teeth

## 5. Malware deep dive - The little engine that couldn't

### 5.1. The money function

### 5.2. FUN_004012e0

### 5.3. CreateFileA

### 5.4. DeviceIoControl

### 5.5. WriteFile

### 5.6. CloseHandle

### 5.7. WinExec

## 6. Conclusion

### 6.1. Pitroxin.A

### 6.2. The analysis process