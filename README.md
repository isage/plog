Codename PrincessLog - by @Princess-of-Sleeping 
---
A complete logging solution for any homebrew, user plugin, kernel plugin. It is more efficient and overall nicer than ShipLog.

* Credits: Princess-of-Sleeping, cuevavirus, Cat

### Usage:

1. Install NetLoggingMgrSettings.vpk.
2. Launch the application and configure your settings. Be sure to save.
3. Add net_logging_mgr.skprx to your config.txt
4. Run `NetDbgLogPc.exe <port>`
   - NOTE: If no port is specified, 9999 will be used by default.
   - To use on other platforms, use netcat or similar. Example netcat command: `nc -kl -w 3 <port>`.
5. Reboot.
Note: If the plugin is already installed and you wish to update the configuration, you may use Update Configuration (along with saving it) without rebooting your system.

In the application you wish to log use:
    ksceKernelPrintf, printf (when SceLibc is included such as in games), or sceClibPrintf

QAF Settings:
    There is options to make more verbose logs used in QA. You can enable these in the manager app.

Note:
    While being much faster than ShipLog, if there is massive amounts of logs the logger may not be able to process them completely and will freeze (ex: taiHEN hexdump). This is unlikely in normal usage.

