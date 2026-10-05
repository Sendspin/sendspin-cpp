# Task stack measurement

`stack_usage.py` finds the deepest call chain of each ESP-IDF task the library runs, from the
call graphs GCC writes with `-fcallgraph-info=su`. The `DEFAULT_*_STACK_SIZE` defaults in
`include/sendspin/config.h` are derived from its output; this directory lets anyone re-derive them.

- `edges.json`: the calls the compiler's graph cannot see (noise-c's function pointers, virtual
  sends, `std::function` callbacks, esp_http_server, esp_transport and esp_event callbacks), plus
  frames for precompiled newlib functions, read from their xtensa `entry` instruction with
  `xtensa-esp32-elf-objdump -d libc.a`.
- `tasks.json`: each task's root, the function its FreeRTOS task starts in.

## Recipe

1. Create a scratch ESP-IDF project that depends on this repository:

   ```yaml
   # main/idf_component.yml
   dependencies:
     sendspin-cpp:
       path: /absolute/path/to/sendspin-cpp
   ```

   ```cmake
   # CMakeLists.txt
   cmake_minimum_required(VERSION 3.16)
   include($ENV{IDF_PATH}/tools/cmake/project.cmake)
   idf_build_set_property(COMPILE_OPTIONS "-fstack-usage" APPEND)
   idf_build_set_property(COMPILE_OPTIONS "-fcallgraph-info=su" APPEND)
   project(stack_usage)
   ```

   `main/CMakeLists.txt` registers a `main.cpp` that includes `sendspin/client.h`. Set
   `CONFIG_IDF_TARGET="esp32"` in `sdkconfig.defaults`, and the optimization level under test:
   `CONFIG_COMPILER_OPTIMIZATION_SIZE=y` for `-Os` (ESPHome's default), nothing for `-Og` (ESP-IDF's
   default). Measure both; the defaults take the larger.

2. Build everything, so every component a task's chain runs through has its `.ci` file (a
   function without one counts as 0 bytes):

   ```bash
   idf.py set-target esp32
   cd build
   ninja
   ```

3. Run the script over the build directory, in an ESP-IDF environment (`. $IDF_PATH/export.sh`,
   which puts the xtensa toolchain on `PATH` and sets `IDF_PATH`):

   ```bash
   PYTHONHASHSEED=0 python3 tools/stack_usage/stack_usage.py /path/to/scratch/build --frameless
   ```

   It prints, per task, the sum of the frames along the deepest simple call path; `--path` prints
   the path itself. Besides the `.ci` files it reads:
   - the toolchain's precompiled newlib (`libc.a`, `libm.a`), `libstdc++.a` and `libgcc.a` with
     `objdump -dr`: each function's frame from its windowed-ABI `entry` instruction, its calls
     from the relocations on its call instructions (`--archive` names others);
   - every object's symbol table, so an alias (a C `__attribute__((alias))`, a complete-object
     constructor or destructor) counts the frame of the function it names;
   - the chip's ROM linker scripts (`$IDF_PATH/components/esp_rom/esp32/ld/*.ld`, `--rom-ld`),
     whose functions have no frame any build can measure.

   It explores every simple path through recursive call cycles rather than following a cycle
   around, which is why it terminates, so a recursion is charged one pass: each function of the
   cycle once (see below). Totals do not depend on iteration order; `PYTHONHASHSEED=0` only keeps
   the choice between equally deep paths the same from run to run.

4. Add the headroom stated in `config.h` (384 bytes) and round up to a 512-byte multiple.

## Keeping the tables current

`--frameless` lists, on stderr, every function a task reaches that has no frame and is not a ROM
function. What is left after the steps above is a handful of assembly routines (the FreeRTOS
port's context switch helpers), newlib syscall stubs ESP-IDF does not link, and libstdc++'s
exception constructors on its terminate path; a new name in that
list means a component is missing from the build or a function needs an entry in `edges.json`'s
`synthetic` table.

`--indirect` lists every function a task reaches that calls through a pointer, marking those
`edges.json` gives targets (`covered`) and those it does not (`NO EDGES`). When a change adds an
indirect call on a task's path (a new virtual send, a new callback), add its targets to
`edges.json`, or the measurement stops at it. An edge source or target that matches nothing is
reported on stderr, and a source none of whose targets match is not marked `covered`. Expected
there: the source `httpd_send_all$isra$0`, which exists only at `-Os`; the target
`httpd_parse_req`, which `-Os` inlines into `httpd_req_new`; the `std::function` call
operator keyed by its mangled name (the new-connection callback), inlined at `-Os`, where the
edge keyed on its caller (`deliver_upgraded()`) stands in for it; and the source task's
`SourceTask::begin_chunk()` and `finish_chunk()`, which the compiler may inline into
`process()`, whose edges cover the same encoder calls; and, in a build without
`SENDSPIN_ENABLE_OPUS`, the `OpusSourceEncoder` targets. Any other name means a table entry has
gone stale.

Every run counts, on stderr, the call cycles each task reaches; `--cycles` lists them, marking
those on the deepest path. The ones the current tree reaches, and how deep each really goes:

- CELT's `quant_partition` calls itself once per band split, with `LM` one lower each time, so
  at the 20 ms frame size (`LM` 3) it nests five deep where the total charges one: up to 4 x 144
  bytes more on the sync task's decode and on the source task's Opus encode; the source task's
  default for an `OPUS` config (`DEFAULT_OPUS_SOURCE_TASK_STACK_SIZE`) adds that margin to its
  bound.
- `opus_decode_frame` and `opus_decode_native` call themselves at most once, for a transition
  or packet-loss frame with no data, which takes the concealment path rather than the band
  decode the total charges.
- lwIP's `lwip_send`/`lwip_sendto` hand a TCP or a non-TCP socket to each other once, and
  `netconn_drain` frees a listener's pending connections, which drain nothing further.
- The 52-function cycle of newlib's `vfprintf`, `malloc` and stdio lock with ESP-IDF's heap and
  `esp_log` closes only through an error log line or assertion raised by an allocation or lock
  made while printing one: a second pass of the error-log tail every total already ends in.
  libstdc++'s terminate cycle closes only through a throw during termination.
- ArduinoJson's parser, serializer and `VariantData::clear()`, one level per nesting level up
  to its limit of 10 (`config.h` lists it), and at `-Og` its `pow10()`, once per exponent bit.

## What it does not model

The result is a static upper bound over the call graph, not a measured high-water mark. It does
not include: recursion deeper than one pass (`--cycles` above), a second interrupt frame, an
`esp_log_set_vprintf()` hook deeper than newlib's `vprintf()`, noise-c's `alloca` extras off
the worst path, ArduinoJson's virtual allocator chain, or the `shared_ptr` disposal at the end
of a protocol tick. `config.h` lists the figures; the on-device high-water check is still owed.
