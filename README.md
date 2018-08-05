# What is this?
A reflexive driver loader to bypass Windows DSE (featuring a custom PE loader)

[Driver Signing Enforcement](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing) is the Windows 7+ kernel driver verification that ensures that only signed drivers can be loaded without Test Mode enabled. This project by default will exploit the capcom.sys rootkit to load an unsigned driver into a system with Test Mode enabled. It provides a simple system to exploit other known signed but exploitable drivers.

# What do I do with this?
It's a PE loader that links against running kernel modules. It's all proof of concept code for my own use, so I can't help you if it breaks or doesn't compile. It does work well, though.
