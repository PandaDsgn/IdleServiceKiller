IDLE SERVICE KILLER - HOW TO INSTALL
====================================

What it is
----------
A tiny Windows service that finds background services which are doing nothing
and stops them to free RAM and CPU. IdleServiceKiller-Setup.exe is everything
you need: it installs the service and is also the window you use to manage it.

Requirements
------------
- Windows 10 or 11, 64-bit.
- An administrator account (you will be asked to approve once).


INSTALL (about 1 minute)
------------------------
1. Double-click  IdleServiceKiller-Setup.exe

   The file is signed by "pandadsgn" (right-click it > Properties > Digital
   Signatures to see it). That is a self-made certificate, not one issued by
   a certificate authority, so Windows does not recognise the publisher and
   may say "Windows protected your PC". If you got this file from pandadsgn,
   click "More info", then "Run anyway".

2. Windows asks for permission to make changes: click Yes.

3. The Idle Service Killer window opens on the "Setup" page.
   Click  "Install / Update".

4. The box under the buttons says "Installed and started", and the status
   line says "installed, running (dry-run)". You are done. You can close the
   window; the service keeps running by itself and starts with Windows.

You can move or delete the Setup file afterwards. The installed copy lives in
C:\Program Files\IdleServiceKiller


IMPORTANT: IT STARTS IN DRY-RUN MODE
------------------------------------
After a fresh install it only WRITES DOWN what it would stop. It does not stop
anything yet. Let it run for a day, then:

1. Open the window again (see "Open it again" below) and go to the "Log" page.
   Lines like  "DRY-RUN would stop SomeService"  show what it would have done.
2. If any of those are services you need, go to the "Settings" page and add
   their name (or a pattern like *name*) to "Never touch", then Save.
3. When you are happy, untick "Dry-run" on the Settings page and Save.
   Windows asks you to confirm, because from then on idle services really
   are stopped.


OPEN IT AGAIN
-------------
- Run  C:\Program Files\IdleServiceKiller\IdleServiceKiller.exe
  (or double-click the Setup file again - it shows the current status).
- Windows asks for permission each time; that is normal.


UPDATE
------
Run the newer Setup file and click "Install / Update". Your settings are kept.


UNINSTALL
---------
Any one of these:
- Open the window, go to "Setup", click "Uninstall".
- Windows Settings > Apps > Installed apps (Windows 10: Apps & features) >
  "Idle Service Killer" > Uninstall. This opens the same window; click
  "Uninstall" there.

Your settings and log are left behind in C:\ProgramData\IdleServiceKiller.
Delete that folder too if you want everything gone.


WHERE THINGS ARE
----------------
Program:   C:\Program Files\IdleServiceKiller\IdleServiceKiller.exe
Settings:  C:\ProgramData\IdleServiceKiller\config.txt
Log:       C:\ProgramData\IdleServiceKiller\log.txt
(The Log page has an "Open data folder" button.)


TROUBLESHOOTING
---------------
- Nothing happens when I double-click:
  Windows is waiting for your approval (look for the shield / flashing taskbar
  icon). If you clicked No, run the file again and click Yes.
- "Not running as administrator, so these buttons will fail":
  Close the window and open it by double-clicking the exe (not from a normal
  terminal), so Windows can ask for approval.
- The status says "installed, stopped":
  Go to Setup and click "Start".
- Antivirus blocks or removes the file:
  It is a new program with a self-signed certificate that manages Windows
  services, which some antivirus tools treat with suspicion. Allow it in your
  antivirus if you trust where you got it.
- Something I need stopped working after I turned dry-run off:
  Open Settings, add that service to "Never touch", and Save. Then start the
  service again: restart the PC, or open Services (press Win+R, type
  services.msc), right-click the service and choose Start.
