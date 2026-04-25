# Stealth-procmon-driver
! Vibdecoded !
This driver trying to replicate functionality of Process monitor driver, but it's awfully replecates it.
Now it's can log:
- Registry:
  Read, Write, Create
- Files:
  Read, Write, Create
- Threads:
  Create, Delete
It's also support mechanism where child process of tracked process inherits tracking as well. And it's logging child launch arguments if there is any.
Now the device symlink for driver <-> user-mode application generating on driver start randomly, so it's will be little bit more sneaky.
It's generating file in C:\ that contains string for user-mode application for device symlink.

! Do not try to run this driver on real machine. !
