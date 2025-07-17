# packer
![Pasted image 20250717133004](attachments/Pasted%20image%2020250717133004.png)\
Well, that's new to me.

![Pasted image 20250717133232](attachments/Pasted%20image%2020250717133232.png)\
The file looks like an ordinary executable, but however, after inspecting the strings, I found something interesting.

![Pasted image 20250717133317](attachments/Pasted%20image%2020250717133317.png)
![Pasted image 20250717133333](attachments/Pasted%20image%2020250717133333.png)\
I then learned that UPX, is, apparently, 'an advanced executable file compressor'. And certainly, if a file has been compressed, there must be a way to decompress it.

![Pasted image 20250717133808](attachments/Pasted%20image%2020250717133808.png)\
Looking at the strings in the decompressed binary executable, I found this particular string:
`Password correct, please see flag: 7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f31613561336633397d`

![Pasted image 20250717133931](attachments/Pasted%20image%2020250717133931.png)\
After pasting the string in CyberChef, I discovered that it's actually hex.
After converting it to ASCII, we have the flag: `picoCTF{U9X_UnP4ck1N6_B1n4Ri3S_1a5a3f39}`