# BadScan
This is a simple litte project for me to experiment with pnet and custom TCP stacks.

# Running
First you will need a machine to run this on, preferably Linux
###### If you want to run this on windows I recommend you to use WSL, it's easier to get it to work there

Build this program using `cargo build --release`, and run the binary in target/release as sudo.
You might need to firewall a port to avoid your OS from dropping packets, by for example using iptables.

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
- Add IPv6 support
- Add scanning of ranges (including adaptive scanning)
- Store results in a database
- Add customizable TCP fingerprints to fool p0f