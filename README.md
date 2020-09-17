STOP: Instead you probably want to use something like this

    easy_pwait() {
        while ps -p $1 >/dev/null; do sleep 5; done
    }

or a more portable version which can only check processes owned by the running user

    easy_pwait() {
        while kill -0 $1 2>/dev/null; do sleep 5; done
    }

unless you need to get the process's exit code.

# What is pwait?

pwait is a small utility to wait for a process to finish. It works much like
the `wait` command built in to bash and other shells, but it can wait for
processes that aren't children of the terminal you run it in.

One advantage of pwait over alternatives (like the shell function above) is
that it can give you the exit code of the process you use it on, which is
useful when you need to know whether a command in another terminal completed
successfully.

Of course, pwait returns its own error codes to indicate whether something goes
wrong. To tell whether a nonzero exit code came from pwait itself or the
program being waited for, look at the log output.

pwait uses the ptrace system call, which means there are some prerequisites
for you to use it:

- It probably only works on Linux, not other UNIX-like OS's. (Support for other
  OS's could be implemented, in principle.)
- You have to have capability support enabled in the kernel and the capability
  manipulation shell utility `setcap` installed on the system
- It must be installed on a filesystem which supports extended attributes, so
  that you can add cap_sys_ptrace to the permitted capabilities list with setcap
- It only works on processes that you can send signals to. In particular, you
  can't pwait for a process running as root (or setuid/setgid) unless you run
  pwait as root. You also can't pwait for a process that is already being traced
  (such as one being run in a debugger).

If this utility turns out to be useful, a future addition might be a
polling mode which allows one to get around these difficulties.

# Other pwaits

This idea is not original. I'm aware of two preexisting programs with the
same intended functionality:

- [FreeBSD pwait](https://github.com/freebsd/freebsd/tree/master/bin/pwait)
  written by Jilles Tjoelker starting in 2004 as part of the FreeBSD project.
  This uses FreeBSD's [kqueue](https://www.freebsd.org/cgi/man.cgi?kqueue)
  mechanism, which doesn't exist in Linux, to register a listener for when
  a process exits. The design philosophy is somewhat similar to the `ptrace`
  technique used by this `pwait` (but `kqueue` is a much better system).
- [William Ting's pwait](https://github.com/wting/pwait) is a shell script
  that implements polling behavior using `ps`.

My implementation of pwait is not based on either of the above, and was
developed independently.

# Requirements

Requires `libcap`.

See the [wiki](https://github.com/diazona/pwait/wiki) for further information on requirements.

# Build

Uses cmake:

```
cmake . && make
```
