# BetterXBDM
BetterXBDM is a WIP fork of the original JTAG XBDM's source code, adding support for debug builds and functions those builds use, instead of just Xbox Neighbourhood.
This is compatible with Bad Update

## Usage
First, if you have them remove JTAG XBDM and HvP2 from your 360 storage medium
Copy BetterXBDM from Releases to your hard drive or USB drive, then add it to your dashlaunch config, replacing JTAG XBDM if you have it.
Then download [my fork of HvP2 with the xbdm hacks removed](https://github.com/theaperturecat/HvP2), add it to your dashlaunch config, replacing the original HvP2 if you have it.


## Building
You need the Xbox 360 SDK and Visual Studio 2010 installed. VS2022 is optional but recommended.

If you are just using VS2010 then build the project normally.
If you are using VS2022 due to changes in MSBuild you cannot use the default VS build rules, so you must put these commands in the VS Powershell window to build the project
```Set-Alias msbuild "E:\vs2022ide\MSBuild\Current\Bin\MSBuild.exe"```
```msbuild /p:Configuration=Release /p:Platform="Xbox 360"```

## Compatibility
Portal: Still Alive has some debug features (via VXConsole) working

## TODO
* Implement more functions
* Try and match more code to how Microsoft's XBDM does it
* Implement better thread safety (How on earth does JTAG XBDM even run with this codebase!?!)
* Clean up code because it is very messy
* Remove the unnecessarily long delays