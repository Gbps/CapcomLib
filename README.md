# What is this?
A reflexive driver loader to bypass Windows DSE (featuring a custom PE loader)

[Driver Signing Enforcement](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing) is the Windows 7+ kernel driver verification that ensures that only signed drivers can be loaded on a system that does not have Test Mode enabled. This project by default will exploit the capcom.sys rootkit to load an unsigned driver and bypass DSE. It also provides a simple system to support exploitation of other known signed exploitable drivers to achieve the same effect.

# What do I do with this?
It's a PE loader that links against running kernel modules. It's all proof of concept code for my own use, so I can't help you if it breaks or doesn't compile. It's in a working state right now, so feel free to use any part of it.
