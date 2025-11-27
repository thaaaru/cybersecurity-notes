---
id: 20240220-linux-workshop
title: "Linux Command Line — 3-Hour Beginner Workshop"
tags: [linux, command-line, teaching, history]
links:
  - "[[zettel-linux-kernel]]"
  - "[[zettel-gnu-project]]"
  - "[[zettel-unix-history]]"
  - "[[zettel-shell-basics]]"
  - "[[zettel-filesystem-layout]]"
  - "[[zettel-permissions-overview]]"
created: 2024-02-20
---

# Linux Command Line — 3-Hour Beginner Workshop

## Overview

A practical introduction to the Linux command line for absolute beginners. This workshop combines historical context, core concepts, and hands-on practice to build fundamental CLI skills.

**Target Audience:** Complete beginners with no prior command-line experience
**Duration:** 3 hours (with breaks)
**Delivery:** Mix of short theory segments, live demos, and guided hands-on exercises

---

## Where It All Began: Unix and Linux History

### Bell Labs Unix (1969)
- Developed at AT&T Bell Labs by Ken Thompson, Dennis Ritchie, and others
- Written in C (1973 rewrite) — making it portable across hardware
- Philosophy: small, modular tools that do one thing well

### The Unix Family Tree
- **BSD** (Berkeley Software Distribution, 1977): Academic Unix variant
- **System V** (AT&T, 1983): Commercial Unix standard
- Major commercial variants:
  - **SunOS/Solaris** (Sun Microsystems, Oracle)
  - **AIX** (IBM, for Power systems)
  - **HP-UX** (Hewlett-Packard)

### The GNU Project (1983)
- Richard Stallman's free Unix-compatible software system
- GNU tools: bash, gcc, coreutils, grep, sed, awk, etc.
- Missing piece: the kernel

### Linux Kernel (1991)
- Linus Torvalds releases Linux 0.01
- Combined with GNU tools → GNU/Linux operating system
- Open source, community-driven development

### Unix-Like Systems Today
Still in production use:
- **BSD family**: FreeBSD, OpenBSD, NetBSD (servers, networking appliances)
- **macOS**: Based on Darwin (BSD/Mach hybrid)
- **Solaris/illumos**: Oracle Solaris, open-source illumos forks
- **AIX**: IBM's Unix for Power systems (enterprise)
- **HP-UX**: HP's Unix (legacy enterprise systems)
- **IBM z/OS**: Mainframe operating system (Unix-like subsystems)

---

## Processor Architectures

### CISC (Complex Instruction Set Computing)
- **x86**: 32-bit Intel/AMD (legacy)
- **x86_64 (amd64)**: 64-bit Intel/AMD (dominant desktop/server)
- Complex instructions, variable length, backward compatibility

### RISC (Reduced Instruction Set Computing)
- **ARM**: Mobile devices, Apple Silicon (M1/M2/M3), AWS Graviton
- **RISC-V**: Open standard, emerging in embedded/HPC
- **Power/PowerPC**: IBM servers (AIX), older Macs
- Simple instructions, fixed length, efficiency focus

### Mainframe
- **IBM Z (s390x)**: Enterprise mainframes running z/OS, Linux on Z
- High reliability, massive I/O throughput

**Linux support**: Excellent across x86_64, ARM, RISC-V, Power, s390x; one kernel for many architectures.

---

## Workshop Agenda (3 Hours)

| Time | Topic | Format |
|------|-------|--------|
| 0:00–0:15 | History & Architecture Overview | Lecture |
| 0:15–0:35 | Core Concepts & Filesystem Layout | Lecture + Demo |
| 0:35–1:05 | Navigation & File Operations | Demo + Hands-on |
| 1:05–1:15 | **Break** | — |
| 1:15–1:35 | Text Viewing & Search | Demo + Hands-on |
| 1:35–2:00 | Pipes, Redirection & Text Processing | Demo + Hands-on |
| 2:00–2:25 | Permissions, Users & Processes | Demo + Hands-on |
| 2:25–2:35 | **Break** | — |
| 2:35–2:55 | Networking, Packages & Disk Tools | Demo + Hands-on |
| 2:55–3:00 | Wrap-up & Resources | Discussion |

---

## Core Concepts

### Kernel vs Distribution
- **Kernel**: Core of the OS (hardware management, process scheduling, memory)
- **Distribution**: Kernel + GNU tools + package manager + desktop environment
  - Examples: Ubuntu, Fedora, Debian, Arch, RHEL, SUSE

### Shell and Terminal
- **Shell**: Command interpreter (bash, zsh, fish)
- **Terminal**: Interface to the shell (gnome-terminal, iTerm2, Alacritty)
- Shell reads commands, executes programs, returns output

### Everything Is a File
- Regular files, directories, devices (`/dev/sda`), processes (`/proc/1234`)
- Unified interface: read/write/open/close

### Paths
- **Absolute**: Starts with `/` (e.g., `/home/user/docs`)
- **Relative**: From current directory (e.g., `docs/file.txt`, `../parent`)
- **Special**: `~` (home), `.` (current), `..` (parent)

### Tab Completion and History
- `Tab`: Auto-complete filenames and commands
- `↑/↓`: Scroll through command history
- `Ctrl+R`: Reverse search history

---

## Filesystem Layout

Standard Linux directory structure:

```
/                   Root of filesystem hierarchy
├── home/           User home directories (/home/alice, /home/bob)
├── etc/            System configuration files (text-based)
├── var/            Variable data (logs, caches, spool)
│   └── log/        System and application logs
├── bin/            Essential user binaries (ls, cat, bash)
├── usr/            Secondary hierarchy
│   ├── bin/        User programs (most executables)
│   └── local/      Locally installed software
├── sbin/           System binaries (root-only tools)
├── dev/            Device files (sda, tty, null)
├── proc/           Virtual filesystem (process/kernel info)
├── sys/            Virtual filesystem (kernel/device tree)
├── tmp/            Temporary files (cleared on reboot)
├── boot/           Bootloader and kernel files
└── lib/            Shared libraries
```

---

## Commands Reference

### Navigation

```bash
pwd                          # Print working directory
ls                           # List files in current directory
ls -l                        # Long format (permissions, size, date)
ls -lh                       # Human-readable sizes
ls -la                       # Include hidden files (start with .)
ls -lt                       # Sort by modification time
ls -ltr                      # Reverse time sort (oldest first)
cd /path/to/dir              # Change directory (absolute)
cd ../relative/path          # Change directory (relative)
cd ~                         # Go to home directory
cd -                         # Go to previous directory
tree                         # Display directory tree
tree -L 2                    # Limit depth to 2 levels
file /bin/bash               # Determine file type
stat file.txt                # Detailed file information
```

### Creating, Copying, Moving, Deleting

```bash
mkdir mydir                  # Create directory
mkdir -p path/to/nested/dir  # Create parent directories as needed
touch file.txt               # Create empty file / update timestamp
cp source.txt dest.txt       # Copy file
cp -r sourcedir/ destdir/    # Copy directory recursively
mv oldname.txt newname.txt   # Rename file
mv file.txt /path/to/dir/    # Move file to directory
rm file.txt                  # Delete file
rm -r directory/             # Delete directory recursively
rm -i file.txt               # Interactive (confirm before delete)
```

### Viewing Text

```bash
cat file.txt                 # Print entire file
less file.txt                # Paginate file (q to quit, / to search)
head file.txt                # First 10 lines
head -n 20 file.txt          # First 20 lines
tail file.txt                # Last 10 lines
tail -n 50 file.txt          # Last 50 lines
tail -f /var/log/syslog      # Follow log file (live updates)
nl file.txt                  # Number lines
nano file.txt                # Simple text editor (Ctrl+O save, Ctrl+X exit)
```

### Search

```bash
find /path -name "*.txt"     # Find files by name pattern
find . -type f -mtime -7     # Files modified in last 7 days
find . -type d               # Find directories only
grep "pattern" file.txt      # Search for pattern in file
grep -r "pattern" /path/     # Recursive search in directory
grep -i "pattern" file.txt   # Case-insensitive search
grep -n "pattern" file.txt   # Show line numbers
grep -v "pattern" file.txt   # Invert match (exclude lines)
rg "pattern"                 # ripgrep (fast alternative to grep)
```

### Pipes, Redirection & Text Processing

```bash
command1 | command2          # Pipe output of command1 to command2
command > file.txt           # Redirect output to file (overwrite)
command >> file.txt          # Redirect output to file (append)
command 2> errors.log        # Redirect stderr to file
command &> all.log           # Redirect stdout and stderr

ls -l | grep ".txt"          # Filter ls output
cat file.txt | sort          # Sort lines
cat file.txt | sort | uniq   # Remove duplicate lines
cut -d',' -f1,3 data.csv     # Extract columns 1 and 3 (CSV)
echo "HELLO" | tr A-Z a-z    # Translate uppercase to lowercase
wc -l file.txt               # Count lines
wc -w file.txt               # Count words
```

### Permissions, Users & Groups

```bash
chmod 755 script.sh          # rwxr-xr-x (owner: rwx, group: rx, other: rx)
chmod u+x script.sh          # Add execute for user (owner)
chmod go-w file.txt          # Remove write for group and other
chown user:group file.txt    # Change owner and group
id                           # Display current user ID and groups
whoami                       # Print current username
groups                       # List groups current user belongs to
sudo command                 # Run command as root
```

**Permission bits:**
- `r` (4): read
- `w` (2): write
- `x` (1): execute
- Example: `755` = `rwxr-xr-x` = 4+2+1, 4+1, 4+1

### Processes & Jobs

```bash
ps                           # Show current shell processes
ps aux                       # Show all running processes
ps aux | grep nginx          # Find specific processes
pgrep nginx                  # Get PIDs by name
top                          # Real-time process monitor (q to quit)
htop                         # Enhanced process monitor (if installed)
kill 1234                    # Send SIGTERM to process 1234
kill -9 1234                 # Send SIGKILL (force kill)
killall firefox              # Kill all processes by name

command &                    # Run command in background
jobs                         # List background jobs
fg %1                        # Bring job 1 to foreground
bg %1                        # Resume job 1 in background
Ctrl+Z                       # Suspend current foreground job
Ctrl+C                       # Interrupt (kill) current foreground job
```

### Services (systemd)

```bash
systemctl status nginx       # Check service status
systemctl start nginx        # Start service
systemctl stop nginx         # Stop service
systemctl restart nginx      # Restart service
systemctl enable nginx       # Enable service at boot
systemctl disable nginx      # Disable service at boot
journalctl -u nginx          # View service logs
journalctl -f                # Follow all system logs
```

### Networking

```bash
ip addr                      # Show network interfaces and IPs
ip addr show eth0            # Show specific interface
ifconfig                     # Legacy network interface tool
ping google.com              # Test connectivity (Ctrl+C to stop)
ping -c 4 8.8.8.8            # Ping 4 times and stop
curl -I https://example.com  # Fetch HTTP headers
curl https://example.com     # Fetch page content
wget https://example.com/file.zip  # Download file
nslookup example.com         # DNS lookup
dig example.com              # Detailed DNS lookup

ssh user@hostname            # Connect to remote host via SSH
ssh -p 2222 user@hostname    # SSH on custom port
scp file.txt user@host:/path # Copy file to remote host
scp user@host:/path/file.txt .  # Copy file from remote host
ssh-keygen -t ed25519        # Generate SSH key pair
```

### Package Management

```bash
# Debian/Ubuntu (apt)
sudo apt update              # Update package lists
sudo apt upgrade             # Upgrade all packages
sudo apt install package     # Install package
sudo apt remove package      # Remove package
sudo apt search keyword      # Search for packages

# Fedora/RHEL (dnf)
sudo dnf check-update        # Check for updates
sudo dnf upgrade             # Upgrade all packages
sudo dnf install package     # Install package
sudo dnf remove package      # Remove package
sudo dnf search keyword      # Search for packages

# Arch (pacman)
sudo pacman -Syu             # Sync and upgrade all packages
sudo pacman -S package       # Install package
sudo pacman -R package       # Remove package
sudo pacman -Ss keyword      # Search for packages
```

### Archives

```bash
tar -czf archive.tar.gz dir/ # Create compressed tarball
tar -xzf archive.tar.gz      # Extract compressed tarball
tar -tzf archive.tar.gz      # List contents of tarball
zip -r archive.zip dir/      # Create zip archive
unzip archive.zip            # Extract zip archive
unzip -l archive.zip         # List contents of zip
```

**Tar flags:**
- `c`: create
- `x`: extract
- `t`: list
- `z`: gzip compression
- `j`: bzip2 compression
- `f`: file

### Disk Information

```bash
df -h                        # Disk space usage (human-readable)
df -i                        # Inode usage
du -sh directory/            # Directory size summary
du -h --max-depth=1          # Size of subdirectories
mount                        # Show mounted filesystems
lsblk                        # List block devices (disks, partitions)
free -h                      # Memory usage (RAM, swap)
```

### Environment & Shell

```bash
echo $SHELL                  # Print current shell
echo $PATH                   # Print executable search path
export VAR="value"           # Set environment variable
env                          # Show all environment variables
alias ll='ls -la'            # Create command alias
unalias ll                   # Remove alias
which python3                # Show full path to executable
type cd                      # Show command type (builtin, alias, file)
history                      # Show command history
!!                           # Repeat last command
!123                         # Repeat command number 123 from history
```

---

## Safety Nets

```bash
man command                  # Read manual page for command
command --help               # Quick help (most GNU tools)
tldr command                 # Simplified examples (if installed)

sudo -l                      # List sudo permissions
sudo -k                      # Invalidate sudo timestamp (require password again)

# Caution with destructive commands
rm -rf /                     # NEVER do this (deletes everything)
rm -r directory/             # Always double-check path before deleting
```

**Best Practices:**
- Use `ls` to verify paths before `rm -r`
- Test regex patterns with `grep` before using with `find -delete`
- Use `-i` (interactive) flag when learning: `rm -ri`, `cp -i`, `mv -i`
- Prefer `trash` or `trash-cli` over `rm` for safer deletion

---

## Practice Blocks

### Block 1: Navigation (10 min)
```bash
# 1. Find your current location
pwd

# 2. List all files including hidden ones
ls -la

# 3. Navigate to /var/log
cd /var/log

# 4. Return to home directory
cd ~

# 5. Create a practice directory structure
mkdir -p ~/workshop/docs/notes
cd ~/workshop
tree
```

### Block 2: Files & Directories (10 min)
```bash
# 1. Create test files
cd ~/workshop
touch README.md notes.txt
mkdir scripts

# 2. Copy and rename
cp notes.txt notes_backup.txt
mv notes_backup.txt notes_old.txt

# 3. Create nested structure
mkdir -p project/{src,tests,docs}
tree

# 4. Clean up (carefully!)
rm notes_old.txt
rm -r project/
```

### Block 3: Search & Text (10 min)
```bash
# 1. Create sample file with content
cat > fruits.txt << EOF
apple
banana
cherry
apple
date
EOF

# 2. View and search
cat fruits.txt
grep "apple" fruits.txt
grep -v "apple" fruits.txt

# 3. Count and deduplicate
wc -l fruits.txt
sort fruits.txt | uniq

# 4. Find files
find ~ -name "*.txt" -type f | head -5
```

### Block 4: Permissions (5 min)
```bash
# 1. Create script
echo '#!/bin/bash' > hello.sh
echo 'echo "Hello, World!"' >> hello.sh

# 2. Check permissions
ls -l hello.sh

# 3. Make executable
chmod +x hello.sh
ls -l hello.sh

# 4. Run it
./hello.sh
```

### Block 5: Pipes & Processing (10 min)
```bash
# 1. List largest files in /usr/bin
ls -lh /usr/bin | sort -k5 -h | tail -10

# 2. Count unique shells
cut -d: -f7 /etc/passwd | sort | uniq -c

# 3. Filter and transform
ps aux | grep -v root | head -5
echo "HELLO WORLD" | tr A-Z a-z

# 4. Log monitoring simulation
# (In a real system)
# tail -f /var/log/syslog | grep error
```

### Block 6: Processes (5 min)
```bash
# 1. List processes
ps aux | head -10

# 2. Find by name
pgrep -l bash

# 3. Background jobs
sleep 30 &
jobs
fg
# (Ctrl+Z to suspend, bg to resume in background)

# 4. System monitor
top
# (Press q to quit)
```

### Block 7: Networking (5 min)
```bash
# 1. Check network interfaces
ip addr

# 2. Test connectivity
ping -c 3 8.8.8.8

# 3. DNS lookup
nslookup google.com

# 4. Fetch web content
curl -I https://example.com
```

---

## System Internals Overview

### Kernel vs Userland

**Kernel Space:**
- Direct hardware access
- Memory management, process scheduling
- System calls interface

**User Space:**
- Applications and tools
- Uses system calls to request kernel services
- Protected memory (cannot crash kernel)

### Init System (systemd)

- First process started by kernel (PID 1)
- Manages services, dependencies, startup sequence
- Replaced older `init` and `upstart` on most modern distros

### Processes and PIDs

- **Process**: Running program instance
- **PID**: Process ID (unique number)
- **PPID**: Parent Process ID
- Init (PID 1) is ancestor of all processes

```bash
ps -ef --forest        # Show process tree
pstree                 # Graphical process tree
```

### Signals

Communication mechanism between processes and kernel:

| Signal | Number | Action | Description |
|--------|--------|--------|-------------|
| SIGINT | 2 | Interrupt | Ctrl+C in terminal |
| SIGTSTP | 20 | Suspend | Ctrl+Z in terminal |
| SIGTERM | 15 | Terminate | Graceful shutdown (default kill) |
| SIGKILL | 9 | Kill | Force kill (cannot be caught) |
| SIGHUP | 1 | Hangup | Reload config (many daemons) |

```bash
kill -l                # List all signals
kill -15 PID           # Send SIGTERM (same as kill PID)
kill -9 PID            # Send SIGKILL (force kill)
```

### Filesystems

**Common Filesystem Types:**
- **ext4**: Default for most Linux distros (journaling, large files)
- **xfs**: High-performance (large files, parallel I/O)
- **btrfs**: Modern (snapshots, subvolumes, copy-on-write)
- **tmpfs**: RAM-based temporary storage
- **/proc**: Virtual filesystem (kernel/process info, read-only)
- **/sys**: Virtual filesystem (kernel/device info)

### Shell Execution and Exit Codes

When you run a command:
1. Shell parses input
2. Forks child process
3. Executes program
4. Returns exit code

**Exit Codes:**
- `0`: Success
- `1-255`: Error (specific meaning varies by program)

```bash
echo "test"
echo $?                # Print exit code of last command (0 = success)

false
echo $?                # Returns 1

command && echo "success"   # Run second command only if first succeeds
command || echo "failed"    # Run second command only if first fails
```

---

## Zettelkasten Integration

### Using This Note

This workshop note serves as a **map/structure note** in your Zettelkasten. It provides:
- Entry point for Linux command-line knowledge
- Structured curriculum for teaching
- Links to atomic concept notes

### Suggested Linked Zettels

Create individual notes for deeper exploration:

- `[[zettel-linux-kernel]]`: Kernel architecture, system calls, modules
- `[[zettel-gnu-project]]`: GNU history, GPL, free software philosophy
- `[[zettel-unix-history]]`: Unix development timeline, philosophy
- `[[zettel-shell-basics]]`: Shell types, scripting, job control
- `[[zettel-filesystem-layout]]`: FHS (Filesystem Hierarchy Standard) deep dive
- `[[zettel-permissions-overview]]`: User/group/other, ACLs, SELinux
- `[[zettel-pipes-redirection]]`: I/O streams, file descriptors, process substitution
- `[[zettel-text-processing]]`: sed, awk, cut, tr, regex patterns
- `[[zettel-process-management]]`: Forking, exec, signals, process states
- `[[zettel-systemd]]`: Unit files, targets, dependencies
- `[[zettel-networking-basics]]`: TCP/IP, DNS, routing, firewalls
- `[[zettel-ssh-security]]`: Key management, config, tunneling
- `[[zettel-package-managers]]`: apt, dnf, pacman internals

### Cross-Linking Strategy

- **Historical context**: Link Unix history to modern Linux distributions
- **Conceptual depth**: Link commands to underlying system calls/internals
- **Security**: Link permissions/users to authentication/authorization notes
- **Networking**: Link CLI tools to network protocol notes
- **Programming**: Link shell scripting to language comparison notes

### Tags

Use tags for flexible retrieval:
- `#linux`: All Linux-related notes
- `#command-line`: CLI tools and usage
- `#teaching`: Instructional materials
- `#history`: Historical context and evolution
- `#workshop`: Structured learning materials
- `#beginner`: Entry-level content

---

## Diagrams and Visual Aids

### Embedding Images in Obsidian

```markdown
![[assets/kernel-userspace-diagram.png]]
![[assets/filesystem-tree.png|300]]          # With width constraint
```

### Suggested Diagrams

1. **Kernel/Userspace Architecture**
   - Visual separation of kernel space and user space
   - System call interface
   - Hardware layer at bottom

2. **Filesystem Hierarchy**
   - Tree visualization of `/`, `/home`, `/etc`, `/var`, etc.
   - Color-code by purpose (config, data, binaries)

3. **Process Lifecycle**
   - States: Running → Sleeping → Stopped → Zombie
   - Transitions (fork, exec, exit, wait)
   - Signal handling

4. **Pipes and I/O Redirection**
   - stdin (0), stdout (1), stderr (2)
   - Pipe symbol connecting processes
   - Redirection arrows to files

5. **Architecture Overview**
   - x86/ARM/RISC-V comparison
   - Register differences, instruction types
   - Use cases (desktop vs mobile vs server)

6. **Unix Family Tree**
   - Timeline from 1969 to present
   - Bell Labs → BSD/System V split
   - GNU + Linux merger
   - Modern derivatives

### Creating Diagrams

Tools:
- **Draw.io**: Free, web-based or desktop
- **Excalidraw**: Sketch-style diagrams (Obsidian plugin available)
- **Mermaid**: Text-based diagrams (native Obsidian support)
- **Graphviz**: Graph/tree generation from code

---

## Additional Resources

### Books
- *The Linux Command Line* by William Shotts (free online)
- *UNIX and Linux System Administration Handbook* by Evi Nemeth et al.
- *How Linux Works* by Brian Ward

### Online
- `man7.org` — Linux man pages
- `tldr.sh` — Simplified command examples
- `explainshell.com` — Parse and explain shell commands

### Practice Environments
- Local VM (VirtualBox, VMware)
- Cloud instances (AWS EC2, DigitalOcean, Linode)
- Containers (Docker)
- WSL2 (Windows Subsystem for Linux)

---

## Workshop Delivery Tips

1. **Start with why**: Explain relevance before diving into commands
2. **Live demos**: Show, don't just tell; make mistakes and recover
3. **Hands-on immediately**: Don't lecture for more than 10 minutes straight
4. **Use tab completion constantly**: Build the muscle memory
5. **Encourage exploration**: "What happens if...?" mindset
6. **Relate to GUI equivalents**: Connect to familiar concepts
7. **Safety first**: Emphasize `-i` flags, `man` pages, and backups
8. **Celebrate small wins**: First successful `grep` pipeline is exciting!

---

## Next Steps After Workshop

- Practice daily: Replace GUI tools with CLI equivalents
- Write shell scripts to automate repetitive tasks
- Explore advanced topics: regex, sed/awk, shell scripting
- Set up a Linux VM or dual-boot system
- Contribute to your Zettelkasten with specific command deep-dives

---

*This workshop note is designed to be reused and adapted. Clone it, modify it, and make it your own.*
