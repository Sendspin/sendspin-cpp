# ESP-IDF build check

A minimal ESP-IDF project that depends on this component by path. CI builds it for `esp32s3` on
each supported ESP-IDF version with the default Kconfig, with `CONFIG_SENDSPIN_ENABLE_OPUS=n`,
and with the player off (`sdkconfig.source_only`, which turns off only the player while the
other roles stay on, so micro-opus comes in for the source's encoder alone), then runs
`check_build.py` to confirm each codec (micro-flac, micro-opus) is resolved, fetched, required by
the component, and linked only when enabled. Nothing here is flashed or run.

## Running

From this directory, in an ESP-IDF environment (`. $IDF_PATH/export.sh`):

```bash
idf.py build
python check_build.py --flac on --opus on
```

For another configuration, start from a clean project (`rm -rf build managed_components
dependencies.lock sdkconfig`) and run, for opus off:

```bash
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.no_opus" build
python check_build.py --flac on --opus off
```

or, for the player off:

```bash
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.source_only" build
python check_build.py --flac off --opus on
```
