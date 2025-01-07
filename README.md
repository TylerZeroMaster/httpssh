# SSH HTTP Tunneling

## What does it do?

The goal is to provide an example of using my httptunnel package to tunnel ssh through http(s).

By tunneling ssh over http you:

- Make it less clear that ssh is available (since it goes through port 80/443 instead of a different port)
- Close one more port on your firewall
- Can use http middlewares to some degree
- Can easily make urls dynamic (maybe like one-time passwords, but instead urls for connections)
- Ensure you are connecting to the correct (https) server with Domain Validation (or better) certificates

## How can I try it?

You can try the ssh tunneling example included on linux/unix systems using openssh.

Get and install the command on both the client and server:

```sh
$ go get github.com/TylerZeroMaster/httpssh
$ go install github.com/TylerZeroMaster/httpssh/cmd/httpssh
```

On the host running ssh, start serving http:
```sh
# You can use the --port option to change the port (default is 8080)
$ httpssh serve
```

Then on your client, configure your ssh connection by adding this to your ~/.ssh/config
```
Host <host-running-ssh-server>
    ProxyCommand httpssh dial http://<host-running-http-server>:<port>/ssh %h %p
```

The `%h` and `%p` are replaced with host and port by your ssh client at runtime (see `man 5 ssh_config` for more details). These are sent via the x-ssh-host and x-ssh-port headers to the server. You can use the http server as a proxy to an ssh server on a different host (but keep in mind that this will add to connection latency). x-ssh-host defaults to localhost and x-ssh-port defaults to 22.

**Note**: https should work too, but it's not configure in the example server.

Next, just ssh like normal:

```sh
$ ssh me@host-running-ssh-server
```

### TOTP URLs

There's also a way to use TOTP urls for ssh. Note, however, that I made the TOTP implementation and I am not a security expert. For more details about the implementation, see [Internal Package TOTP](#internal-package-totp).

You can enable totp urls like this:

First create a key config (this assumes you are doing it on the client):

```sh
# These options are the defaults, see help for more details
$ httpssh keygen my-key.bin --period 1 --sha256
```

Copy the key to the server, then run:

```sh
$ httpssh serve --totp-config my-key.bin
```

The server will start in totp mode if it is given one or more config paths.

Then on your client, configure your ssh connection by adding this to your ~/.ssh/config
```
Host <host-running-ssh-server>
    ProxyCommand httpssh dial http://<host-running-http-server>:<port>/{{code}} %h %p --totp-config my-key.bin
```

`{{code}}` is replaced with the actual code during a connection attempt

Next, just ssh like normal:

```sh
$ ssh me@host-running-ssh-server
```

Except now you will use a unique url each time.

### Bonus points: Port 80 with least privilege (optional)

On your server, update your nftables as such:

```sh
# Create table nat for IPv4 and IPv6
sudo nft 'add table inet nat'
# This little packet originated from localhost (you only need this one if you are running your server on the same host as the client)
sudo nft '
add chain inet nat OUTPUT { type nat hook output priority -100; policy accept; }
add rule inet nat OUTPUT oifname "lo" tcp dport 80 counter redirect to :8080
'
# This little packet originated from outside (you only need this one if you are running your server on a different host than the client)
sudo nft '
add chain inet nat PREROUTING { type nat hook prerouting priority -100; policy accept; }
add rule inet nat PREROUTING iifname != "lo" tcp dport 80 counter redirect to :8080
'
```

Then you no longer need root to accept connections from port 80 because they will be redirected to unprivileged port 8080. Update your ssh config to remove the port.

## Internal Package TOTP

The totp package is internal because it's just an example. I suspect I would need to spend more time and effort to make a truly secure implementation.

My implementation is essentially RFC 4226/6238 except it (1) uses the entire hash instead of a small part of it and (2) defaults to sha256 instead of sha1.

The 1064 byte key config includes a 1 byte version, 16 byte id, 1024 byte secret, 8 byte period, and 1 byte algorithm id saved and loaded from a little endian binary file.

This package is used in the example client/server thusly:

1. Internal package TOTU generates HMAC sum, concatenates key ID + HMAC sum, returns base64 encoded--url encoding--representation.
2. Client replaces instances of `{{code}}` within the connection string with the above key id/totp code.
3. Server gets `{code}` path value from request.
4. Internal package TOTU validates the code, picking the key based on the key id.
5. If validation fails, send either 404 for unexpected error, or 401 if the key was already used; else add the key to a circular list of the last 100 keys used.

## Where to next?

Not sure if these will ever be finished, but:

- Finish writing tests
