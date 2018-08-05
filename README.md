# CapcomLib
A reflexive driver loader to bypass Windows DSE (featuring a custom PE loader)

# What is this?
[Driver Signing Enforcement](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing) is the Windows 7+ kernel driver verification that ensures that only signed drivers can be loaded without Test Mode enabled. This project can be used to exploit the capcom.sys rootkit to load an unsigned driver into a system with Test Mode enabled.

# What do I do with this?
It's a PE loader that links against running kernel modules. It works well. It's all proof of concept code for my own use, so I can't help you if it breaks or doesn't compile.
