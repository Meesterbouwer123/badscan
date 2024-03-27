# BadScan
This is a simple litte project for me to experiment with pnet and custom TCP stacks.

# Running
This program is recommended to run on linux, since on windows you need something like WinPcap or nPcap to run it. Also (i assume) getting the OS to not drop the packets is harder.
On WSL it runs surprisingly well, not even port forwarding needed so far :D

# FAQ
### Why the name?
I know my coding skills, this will (probably) become the largest semi-working spagetthi codebase you can imagine.
For the name I also took some inspitation from [matscan](https://github.com/mat-1/matscan).

### It crashes with `cannot open input file 'Packet.lib'`
This is a common error on windows, it happens because the linker can't find the `Packet.lib` library which is required by pnet. The solution is adding the lib folder to an environment variable the linker checks:
```powershell
$env:LIB += ";$(Get-Location)\lib"
```
more info [here](https://github.com/libpnet/libpnet?tab=readme-ov-file#windows)

# TODO
- Add TCP semi-stateless scanner
- Add more protocols (minecraft SLP, ~~MCBE raknet ping~~, etc)