# Capstone-Project

####The project was intended to be my senior capstone research project after i realized writing my own antir-virus kernel driver was probably going to take me way too long to accomplish in one semester. The goal of the project was to create shellcode launcher that would ultimately bypass anti-virus / EDR products. However, since I was not shelling out money for this assignment, I was limited to free products available. The tested prodocuts were: Defender, ESET | ESET Live, BitDefender, MalwareBytes, TotalAV, and Avira. The malware was packed with the following techniques:

1)	Dynamic Function Resolution – Used to hide functions from the IAT.
2)	Manual GetProcAddress & Manual GetModuleHandle functions – Used to hide these functions from the IAT.
3)	API hashing – Used to remove the need for function name strings to be stored within the executable removing a potential detection mechanism.
4)	Custom written – bypassing the hashing detection methodology.
5)	MSFVenom Windows Meterpreter Shellcode Payload – A widely signatured payload that should be easily detected by AV engines.
6)	AES encryption of the Meterpreter payload at rest – Used to remove the possibility of the meterpreter payload being signature detected while on disk.

  a.	The tiny AES library is used to encrypt / decrypt payloads without needing to use Windows APIs that may be hooked by security solutions.
8)	RC4 encryption of all strings used within the malware – Used to remove the possibility of strings being signatured or detected when scanning the malware application.
9)	Indirect System Calls – Used to call system calls directly bypassing any API hooking the security solution has implemented to detect malicious code execution at run time.
 
  a.	Indirect system calls are used to perform API Unhooking of the entire NTDLL module loaded into memory.
  
  b.	Indirect system calls are used to load the decrypted meterpreter payload into memory & executing it via a new thread. This bypasses AV’s ability for detection when executing the shellcode.
10)	Self-Deletion of the payload from disk. – Used to remove the payload from disk so it cannot be analyzed further.
11)	Removal of the C Runtime Library – Less bloat in the application, functions of the C Runtime are implemented manually. Also ensures the payload can run on any Windows 10 x64 system.
12)	 Hiding of the console window – ensures a victim user does not become suspicious that something happened after execution through witnessing a command prompt flash.

####These techniques were adapted from previous research and the maldevacademy content. Some of the code introduced was used one for one, some required adjustments to meet my criteria for the project.

####The biggest regret I have for this project was not implementing ETW bypassing & not implementing memory encryption. However, since the meterpreter shellcode does not allow for (as far as i know) setting sleep settings, we are unable to encyrpt the shellcode at rest. This was problematic because, our payload when it was detected almost always got detected by memory scanners.

####Results - Defender Bypassed, MalwareBytes Bypassed, TotalAV Bypassed, BitDefender Detected, Avira - installation could not be completed, ESET & ESET Live Detected using memory scanner.
