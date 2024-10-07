# Firmware info
- Device name: **N200RE V5**
- Build version: **V9.3.5u.6437_B20230519** 
- Download link: https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/204/ids/36.html
- Authentication: Yes (Login as account on firmware's web interface)
- Affect: Unknown number of ToTotlink firmware that uses function `Validity_check`.

# Description and Impact
Totolink is using function `Validity_check` to fix OS command injection vulnerability. An attacker can bypass this filter using character `%`, exploit the format string at `snprintf` function to execute OS system commands.

# Root-casue
Function `Validity_check` finds blacklisted strings / characters such as ```$ ` | ; &```
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/1.png)

After the validation, the server executes system command when it can't find any blacklisted characters
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/2.png)

The program is calling some external libraries

![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/3.png)

Function `doSystem` is using function `vsnprintf` to craft system command and then execute using `system`.

![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/4.png)

Functions`snprintf` and `vsnprintf` are vulnerable against format string attack (source: Format string attack | OWASP)
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/5.png)


# Steps to reprocedure
when use the `ping` or `traceroute` feature, attacker can inject character `%x` in the IP address
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/6.png)

The server responses with a hex value, suggesting it could be a format string vulnerability
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/7.png)

When attacker uses payload `%whoami`, the server response busybox's output. It suggests that the string `whoami` was delivered to the `busybox` interpreter
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/8.png)
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/9.png)

When attacker sent the same payload to `traceroute`, the command was executed sucessfully
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/10.png)
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/11.png)

Due to limitation of the `%` as the string format, some command can't be executed. The reason is the first character
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/12.png)
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/13.png)

Attacker can use absolute path to bypass this issue, executing system command
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/14.png)
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/15.png)

When attacker uses ping feature to exploit, it might be command failed to run because the flag `-w` for command `ping` is hard-coded.
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/16.png)
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/17.png)

Attacker can use the syntax that calls `/bin/bash` or `/bin/sh` to execute the command that does not contain `-w`, therefore avoid the command execution error
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/18.png)
![image](https://github.com/meli0dasH4ck3r/CVE_TOTO-LINK_BYPASS-TO-RCE/blob/main/POC/19.png)

# Recommends
- Add `%` to blacklist
- Check the logic of `doSystem` to avoid format string error.

# Reference
- https://owasp.org/www-community/attacks/Format_string_attack
- https://www.cs.cornell.edu/courses/cs3410/2008fa/MIPS_Vol2.pdf
- https://en.wikibooks.org/wiki/MIPS_Assembly/Register_File

# Author 
- NGUYEN VIET KHOI 
