# PEspy  

A **C** tool for analyzing **PE (Portable Executable)** files on Windows, focusing on exploring the **DOS Header** and the internal structure of executables.  

---

## Features:
- Reads and parses the **DOS Header**  
- Detailed display of header fields (`e_magic`, `e_lfanew`, etc.)  
- Validates if the file is a real PE  
- Base for future PE parsing modules  

---

## How to Compile:

```bash
gcc -o pespy main.c lib/isPE.c
```

## How to Use:
```bash
./pespy <path_to_executable.exe>
```

## Example:
```bash
./pespy C:\\Windows\\System32\\notepad.exe
```
### Expected output:
```bash
The file notepad.exe is a valid PE file.

===== DOS HEADER =====
File: notepad.exe
e_magic   (MZ header):                  0x5A4D
e_cblp    (Bytes on last page):         0x0090
...
e_lfanew  (Offset to PE header):        0x000000F8
```

