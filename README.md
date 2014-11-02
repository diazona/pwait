STOP: Instead you probably want to use something like this

    pwait_poll() {
        while ps -p $1 >/dev/null; do sleep 5; done
    }

or a more portable version which can only check processes owned by the running
user

    pwait_poll() {
        while kill -0 $1 2>/dev/null; do sleep 5; done
    }

unless you need to get the process's exit code.

For your convenience, pwait includes a shell script that provides this function.
It's called `pwait_poll.sh`; just source it in your shell and then you can call
`pwait_poll PID [DELAY]`.

# What is pwait?

pwait is a small utility to wait for a process to finish. It works much like
the `wait` command built in to bash and other shells, but it can wait for
processes that aren't children of the terminal you run it in.

The advantage of pwait over the pwait_poll shell function above is that the
full pwait can give you the exit code of the process you use it on, which is
useful when you need to know whether a command in another terminal completed
successfully.

Of course, pwait returns its own error codes to indicate whether something goes
wrong. To tell whether a nonzero exit code came from pwait itself or the
program being waited for, look at the log output.

pwait uses one of two methods to collect the exit code of its target process:

- the ptrace system call, which attaches to the target process like a debugger
- the netlink connector, which registers with the kernel to be notified every
  time a process exits (or forks, execs, etc.) and ignores all such notifications
  except for the process you ask it to watch

Needless to say, this is fairly low-level system stuff, so it comes with a few
caveats:

- It probably only works on Linux, not other UNIX-like OS's. (Support for other
  OS's could be implemented, in principle.)
- You have to have capability support enabled in the kernel and the capability
  manipulation shell utility `setcap` installed on the system (unless you run
  pwait as root or seteuid root)
- It must be installed on a filesystem which supports extended attributes, so
  that you can add cap_sys_ptrace and/or cap_net_admin to the permitted
  capabilities list with setcap (again, unless you run it as root)
- The ptrace method only works on processes that you can send signals to. In
  particular, you can't pwait for a process running as root (or setuid/setgid)
  unless you run pwait as root. You also can't pwait for a process that is
  already being traced (such as one being run in a debugger). The netlink method
  doesn't suffer from these particular limitations, so it's the default.

For completeness, pwait also implements a polling mode which does the same thing
as the pwait_poll shell function. This mode cannot retrieve the exit code of the
process, though, and it also won't catch the exact time at which the process ends.

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
