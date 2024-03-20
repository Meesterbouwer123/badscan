# Insert cool name here
This is a simple litte project for me to experiment with pnet.

# Running
This program is recommended to run on linux, since on windows you need something like WinPcap or nPcap to run it. Also getting the OS to not drop the packets is harder.
On WSL it runs surprisingly well, not even port forwarding needed so far :D

# FAQ
### It crashes with `cannot open input file 'Packet.lib'`
This is a common error on windows, it happens because the linker can't find the `Packet.lib` library which is required by pnet. The solution is adding the lib folder to an environment variable the linker checks:
```powershell
$env:LIB += ";$(Get-Location)\lib"
```
more info [here](https://github.com/libpnet/libpnet?tab=readme-ov-file#windows)

# TODO
- Add TCP semi-stateless scanner
- Add more protocols (minecraft SLP, MCBE raknet ping, etc)