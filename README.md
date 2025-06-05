# 🪱 tapeworm

**An SSH client that tunnels through DNS.**
Built for censorship resistance, identity-aware access, and ultra-portable deployment --- with a single binary.

---

## ✨ What Is tapeworm?

`tapeworm` is a **hardcoded SSH-over-DNS tunneling system**. The client connects through DNS, tunnels traffic to your SSH server, and launches a login shell --- no configuration, no extra setup. Just run the binary.

It's designed for **drop-in deployment**: you hand out the client binary, users run it, and they're dropped into an SSH session tunneled over DNS.

---

## 🧩 How TransIRC Uses It

The full stack used at [transirc.chat](https://transirc.chat):

```txt
User runs tapeworm-client
    ↓
DNS Tunnel via port 5353/UDP
    ↓
tapeworm-server
    ↓
Custom SSH Server (supports PROXY protocol)
    ↓
IRC Terminal Environment (NickServ-authenticated)
    ↓
Weechat or other IRC Client

```

### What happens:

-   🔐 **Client IP is preserved** via PROXY protocol v1 at every step

-   🧠 **NickServ-based SSH authentication** ensures verified IRC identity

-   🌐 **IRC access via Weechat** + custom terminal environment

-   🧳 **No tun/tap required** --- it's a proxy, not a VPN

* * * * *

🏁 Quick Start
--------------

### 🖥️ Server

```
# Compile the server binary
go build -o tapeworm-server tapeworm-server.go

# Start it with your config
./tapeworm-server config.conf

```

-   Listens on `UDP/5353` for incoming DNS tunnel clients

-   Forwards SSH traffic to your backend SSH server

-   Sends PROXY v1 headers so backend knows the real client IP

### 💻 Client

```
# Compile the client
go build -o tapeworm-client tapeworm-client.go

# Or just run the prebuilt binary (hardcoded to your domain + user)
./tapeworm-client

```

-   No arguments needed --- everything is embedded

-   Immediately connects to the DNS tunnel server

-   Launches an SSH session through the tunnel

* * * * *

🔐 Why PROXY Protocol?
----------------------

Every hop in this system uses **PROXY protocol v1** to preserve the original IP. This allows:

-   Accurate session logging

-   Proper NickServ authentication on IRC

-   Enforcing bans/rate-limits per user

-   Seamless identity flow across tunnel ➝ SSH ➝ IRC

* * * * *

🪛 Architecture Overview
------------------------

```
[ tapeworm-client ]
     │  DNS packets over UDP 5353
     ▼
[ tapeworm-server ]
     │  PROXY v1 header
     ▼
[ custom SSH server ]
     │  NickServ-auth
     ▼
[ IRC + Weechat + SSH Env ]

```

* * * * *

🧪 Features
-----------

-   ✅ Standalone binary (no tun/tap, no config)

-   ✅ DNS tunnel over UDP 5353

-   ✅ PROXY protocol v1 support

-   ✅ Designed to work with NickServ-auth SSH setups

-   ✅ Portable (works on Linux, targeting Windows next)

-   ✅ Optimized for locked-down and censored networks

* * * * *

🏳️‍⚧️ About TransIRC
---------------------

[TransIRC](https://transirc.chat) is a welcoming, self-hosted IRC community for trans and gender questioning individuals. Our SSH and DNS-tunnel system was built to:

-   Provide safe IRC access in hostile or filtered environments

-   Maintain accountability with NickServ-verified identities

-   Let users access a full terminal-based IRC + utility experience over SSH

We're releasing `tapeworm` so others can build similar secure and identity-aware networks.
