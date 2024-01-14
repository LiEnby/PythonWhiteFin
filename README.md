# PythonWhiteFin

revert cobra blackfin patches added in 3.60

Cobra Blakfin patch is as follows:
```
time = sceKernelGetSystemTimeWide()
do_gc_authentication()
time2 = sceKernelGetSystemTimeWide()

if((time2 - time) > 50000) goto fail;
```

or tl;dr if gc authentication takes longer than 50000 microseconds, then the authentication fails.
