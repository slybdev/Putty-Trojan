# 🛡️ Malware Analysis: Disguised PuTTY Trojan

A deep-dive analysis of a malware sample that disguised itself as PuTTY but executed a hidden PowerShell payload and attempted to establish an encrypted reverse shell.

---

## 🎯 Objective

To analyze and understand the behavior of a malware sample posing as PuTTY using both static and dynamic analysis techniques. The goal was to uncover its execution flow, hidden payloads, and network communication patterns.

---

## 🧠 Skills Learned

- Static and Dynamic Malware Analysis  
- PowerShell Payload Extraction  
- Process Monitoring with Procmon  
- Base64 Decoding Techniques  
- DNS Spoofing via hosts File Manipulation  
- Traffic Analysis with Wireshark  
- Identifying Encrypted Remote Shells  
- Using ncat and TCPView for Reverse Shell Detection

---

## 🛠️ Tools Used

- [VirusTotal](https://www.virustotal.com)  
- [FLOSS (FireEye)](https://github.com/mandiant/flare-floss)  
- [Procmon (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)  
- [Wireshark](https://www.wireshark.org/)  
- [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview)  
- [ncat (Nmap)](https://nmap.org/ncat/)  
- [Cmder](https://cmder.net/)  
- Base64 Decoder  
- Windows Hosts File

---

## 🔬 Analysis Walkthrough

### 1. 🔍 Static Analysis

- **Hash Generated:**  
  `0c82e654c09c8fd9fdf4899718efa37670974c9eec5a8fc18a167f93cea6ee83`

- **VirusTotal Scan:**  
  Flagged as **malicious by 61 out of 72 vendors**

- **FLOSS String Extraction:**  
  Attempted string extraction; output was long and obfuscated with no meaningful indicators found.

---

### 2. ⚙️ Dynamic Analysis

- **Behavior on Execution:**  
  - Brief PowerShell window flashes  
  - Real PuTTY opens to avoid suspicion

- **Procmon Observation:**  
  - Tracked PuTTY’s PID  
  - Parent process spawned several **PowerShell** instances  
  - Found **Base64-encoded** script in command line  
  - Decoded it to reveal a malicious **PowerShell payload**

---

### 3. 🌐 Network Analysis

- **Wireshark Traffic Capture:**  
  - Detected DNS resolution attempt to:  
    `bonus2.corporatebonusapplication.local`
  - Repeated **retransmission on port 8443**

- **DNS Spoofing for Redirection:**  
  - Modified hosts file:  
    `127.0.0.1    bonus2.corporatebonusapplication.local`

- **Loopback Monitoring:**  
  - Captured traffic again using Wireshark  
  - Confirmed TLS-encrypted traffic over **port 8443**

- **Reverse Shell Detection:**  
  - Opened **ncat** listener on port 8443:  
    `ncat -nvlp 8443`  
  - Identified a connection attempt with **encrypted payloads**

---

## 🔐 Key Findings

- Malware attempts to maintain stealth by opening real PuTTY  
- Injects a PowerShell reverse shell encoded in base64  
- Uses custom DNS and encrypted communication over port 8443  
- TLS encryption makes payload inspection impossible without the correct certificate

---

## 📸 Screenshots

> 📌 Add images showing:
> - VirusTotal scan result  
> - FLOSS string output  
> - Procmon tree & command line  
> - Base64 decoding  
> - Wireshark DNS resolution  
> - TCPView showing active connections  
> - ncat catching the encrypted connection

---![Screenshot putty 2](https://github.com/user-attachments/assets/bd9b642a-cd0c-492f-b8a7-4f5da24ac18d)
![Screenshot putty 4](https://github.com/user-attachments/assets/b8b14a47-6411-4fd6-a022-6a3a7859c586)
![Screenshot putty 14](https://github.com/user-attachments/assets/d1177b71-bd19-4785-b44c-95dbdb9a3e76)
![Screenshot putty 18](https://github.com/user-attachments/assets/4f5923f5-db22-478b-ada2-6943067fdb98)
![Screenshot putty 17](https://github.com/user-attachments/assets/c5903a5d-7848-4147-a1bd-a7d9b0d468d0)
![Screenshot putty 19](https://github.com/user-attachments/assets/086f004a-f08d-4f6c-b5da-45153d2f1457)
![Screenshot putty 22](https://github.com/user-attachments/assets/022d6177-3fb4-4340-aaab-b6096ec33354)

![Screenshot putty 11](https://github.com/user-attachments/assets/96ff3e4a-fc27-4af6-ab34-50ab8d74af95)
![Screenshot putty 10](https://github.com/user-attachments/assets/688c3fd9-6315-4d96-83cd-3b2f11e2e53d)
![Screenshot putty 30](https://github.com/user-attachments/assets/db1bf918-c470-4905-91a7-a704cdc5770d)

## 🗣️ Conclusion

This case study demonstrates how attackers use legitimate tools as a disguise while executing malicious payloads in the background. It emphasizes the importance of monitoring **network behavior**, **encoded payloads**, and **post-execution artifacts** in malware analysis.

---

## 💬 Feedback

Feel free to open an issue or connect with me on [LinkedIn](https://www.linkedin.com/) if you have suggestions, questions, or tips!

---

## 📁 File Hash

0c82e654c09c8fd9fdf4899718efa37670974c9eec5a8fc18a167f93cea6ee83
