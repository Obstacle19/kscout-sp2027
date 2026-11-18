# Compatibility launcher packaging

This directory retains the upstream npm launcher build and container helpers.
Build the Rust CLI using the [repository README](../../README.md#build).

`build_npm_package.py` supports manual package preparation. Native packages require
`--vendor-src` to point to a prepared directory of native artifacts. Upstream npm
release staging and publishing automation are not included in this snapshot.
