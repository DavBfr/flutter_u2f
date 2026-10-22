# Vendored hidapi

These sources are vendored so that the `u2f` Swift package is self-contained
and has no external dependency.

- Upstream: https://github.com/libusb/hidapi
- Version: 0.14.0
- License: HIDAPI (BSD-style / GPLv3 / original), see `LICENSE.txt`

The `hidapi.h` copy used for ffigen lives at `macos/hidapi.h`.
