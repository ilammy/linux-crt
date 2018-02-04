CreateRemoteThread for Linux
############################

CreateRemoteThread_ (thread injection) for Linux.

.. _CreateRemoteThread: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682437(v=vs.85).aspx

Limitations:

* works only for x86_64 applications (64-bit)
* works only for dynamically linked applications
* works only for applications using glibc
* works only with enabled debugging (i.e., ptrace_scope set to zero,
  the target process is dumpable, or you have CAP_SYS_PTRACE)
* unsafe when applied to single-threaded applications

License
=======

GPLv2: see `LICENSE <LICENSE>`_.
