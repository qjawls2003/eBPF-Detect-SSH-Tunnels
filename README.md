# eBPF-Detect-SSH-Tunnels
Detecting the presence of SSH tunnel

**Description**: An eBPF agent to detect the presence of SSH tunneling.

**Purpose**: This program will reduce the amount of manual work when conducting forensics on suspicious user activities.



## Idea

The core framework of this program revolves around SSH's calling of the `connect` syscall on the same process that initially spawned the SSH connection.

![tunnel_5](https://github.com/qjawls2003/eBPF-Detect-SSH-Tunnels/assets/35247051/ec12b7ac-c014-435e-b863-d12676e7b365)

![tunnel_4](https://github.com/qjawls2003/eBPF-Detect-SSH-Tunnels/assets/35247051/d099c0c7-6a9e-426e-9017-3293bc1374b8)

## Usage
```
sudo ./sshtunnel [-a] [-p] [-v] [-w] [-h] [--max-args MAX_ARGS]
```
```
       ./sshtunnel           # trace all ssh-spawned execve syscall\
       ./sshtunnel -p        # printf all logs\
       ./sshtunnel -v        # verbose events
       ./sshtunnel -w        # verbose warnings
       ./sshtunnel -h        # show help
```
## Installation

Linux Distrubtion with eBPF
```
git clone https://github.com/qjawls2003/eBPF-Detect-SSH-Tunnels
cd /eBPF-Detect-SSH-Tunnels
sudo ./sshtunnel -p
```

If you want to **Make** your own executable:
```
git clone --recurse-submodules https://github.com/qjawls2003/eBPF-Remote-Client-Tracing
sudo apt-get install bpftool
sudo apt-get install clang
sudo apt-get install libbpf-dev
sudo apt-get install gcc-multilib
sudo apt-get install llvm  
make
```
