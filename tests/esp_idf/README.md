# ESP-IDF build check

A minimal ESP-IDF project that depends on this component by path. CI builds it for `esp32s3` on
each supported ESP-IDF version, once with the default Kconfig and once with
`CONFIG_SENDSPIN_ENABLE_OPUS=n`, then runs `check_build.py` to confirm each codec (micro-flac,
micro-opus) is resolved, fetched, required by the component, and linked only when enabled.
Nothing here is flashed or run.

## Running

From this directory, in an ESP-IDF environment (`. $IDF_PATH/export.sh`):

```bash
idf.py build
python check_build.py --opus on
```

For the opus-off configuration, start from a clean project (`rm -rf build managed_components
dependencies.lock sdkconfig`) and run:

```bash
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.no_opus" build
python check_build.py --opus off
```
