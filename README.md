# Tempesta xFW

An XDP/TC eBPF volumetric DDoS protection solution.

## Documentation


See Tempesta Escudo [Wiki](https://github.com/tempesta-tech/xfw/wiki) for Tempesta
xFW documentation.


## Build

Ubuntu 24 LTS and at least clang-19 are required.

```bash
sudo apt install -y cmake make xdp-tools \
    clang clang-19 clang-tools-19 clang-tidy-19 clang-format-19 \
    libboost-all-dev flatbuffers-compiler libflatbuffers-dev libprotobuf-dev libgrpc++-dev \
    linux-tools-common libspdlog-dev libmaxminddb-dev libbpf-dev libbpf-tools libgtest-dev \
    linux-tools-generic linux-cloud-tools-generic
```

An example how to make a debug build of the project:

```bash
git submodule update --init --recursive
DEBUG=3 make -j$(nproc) clean all
sudo make install
```

By default, all project data will be installed to `PREFIX=/opt/tempesta`.
You can override this location by specifying a different PREFIX when running `make install`, for example:

```bash
make install PREFIX=/custom/path
```

To see a list of available make targets and their descriptions, run:

```bash
make help
```


### Installation and Usage

After installing the project, you can start the service using:

```bash
$(PREFIX)/bin/xfwctl --start
```

All available script options and commands can be viewed with:

```bash
$(PREFIX)/bin/xfwctl --help
```

For development or local testing, you can run the script without installation
by setting the `TEMPESTA_XFW_PATH` environment variable manually:

```bash
TEMPESTA_XFW_PATH=./BUILD ./xfw/xfwctl --start
```

If you installed the project with a custom prefix, for example:

```
make install PREFIX=/custom/path
```

then you should run the script with the corresponding `TEMPESTA_XFW_PATH`:

```bash
TEMPESTA_XFW_PATH=/custom/path ./xfw/xfwctl --start
```


## Integration Python testing

Integration Python tests can be found in `xfw/t/func`. Read corresponding
[README.md file](xfw/t/func/README.md) to prepare environment and run functional tests.


## Functional and unit tests

```
make test
```


## Debugging

If you build Tempesta xFW in debug mode, you'll see BPF debug messages (see `bpf_trace_printk`
[documentation](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html) for details):
```
DEBUG=1 make -j`nproc`
```

Example of reading logs:
```
sudo cat /sys/kernel/tracing/trace_pipe
```

