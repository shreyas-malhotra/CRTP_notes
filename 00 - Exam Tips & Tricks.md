- Anything within the lab will be in scope for the exam except for persistence and attacks requiring bruteforcing (ex: kerberoasting and AS-REProasting)
- Use RDP access, preferably with a good client like Remmina, and set up shared folder access, also make sure to test it before the exam.
- Run BloodHound legacy for better compatibility with the exam environment.
- Run BloodHound on your host machine, not the student VM, since it will slow down the VM.
- Have your tools ready in a zip file before the exam so that they are easily transferable to the student VM.
- Make sure that the tools do not get detected by Windows Defender, since the AVs deployed in the exam environment are completely up to date; obfuscate the tools/payload if necessary.
- Use HFS - HTTP File Server, wherever required.
- Remember to use Loader.exe and InviShell, wherever required, some commands may not mention the use of Loader.exe, but consider it understood that we will use it wherever possible.
- Unless specified otherwise, all the PowerShell based tools (especially those used for enumeration) are executed using InviShell to avoid verbose logging. Binaries like Rubeus.exe may be inconsistent when used from InviShell, run them from the normal command prompt.
- Please remember to turn-off or add an exception to your student VMs firewall when your run listener for a reverse shell.
- The C:\AD directory is exempted from Windows Defender but AMSI may detect some tools when you load them. The lab manual uses the following AMSI bypass:
- If you want to turn off AV on the student VM after getting local admin privileges, please use the GUI as Tamper Protection incapacitates the 'Set-MpPreference' command.

Useful websites I found:
- https://wadcoms.github.io/
- https://zer1t0.gitlab.io/posts/attacking_ad/
- https://0xd4y.com/2023/04/05/CRTP-Notes/
- https://0xd4y.com/misc/CRTP_Notes.pdf
- https://dudisamarel.gitbook.io/crtp-notes
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse
- https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/
- https://swisskyrepo.github.io/InternalAllTheThings/
- https://powersploit.readthedocs.io/en/latest/
- https://notes.sfoffo.com/active-directory

Useful blogs I found:
- https://medium.com/@dineshkumaar478
- https://medium.com/@dineshkumaar478/my-crtp-journey-2025-how-i-passed-lessons-learned-e8b1305e830c
- https://happycamper84.medium.com/thm-walkthrough-list-ad-stuff-95280f400bec
- https://www.hackthebox.com/blog/introduction-to-active-directory
- https://www.hackthebox.com/blog/active-directory-hardening-pentester-vs-soc
- https://www.hackthebox.com/blog/active-directory-penetration-testing-cheatsheet-and-guide
- https://www.hackthebox.com/blog/active-directory-misconfigurations
- https://www.hackthebox.com/blog/active-directory-attacks-history-tactics-defenses

Cheatsheets:
- https://github.com/drak3hft7/Cheat-Sheet---Active-Directory