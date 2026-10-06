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

4. Add the 384-byte margin (see [Margin and rounding](#margin-and-rounding)) and round up to a
   512-byte multiple.

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
  to its limit of 10, and at `-Og` its `pow10()`, once per exponent bit.

## What it does not model

The result is a static upper bound over the call graph, not a measured high-water mark. It does
not include: recursion deeper than one pass (`--cycles` above), a second interrupt frame, an
`esp_log_set_vprintf()` hook deeper than newlib's `vprintf()`, noise-c's `alloca` extras off
the worst path, ArduinoJson's virtual allocator chain, or the `shared_ptr` disposal at the end
of a protocol tick. The bounds are also conservative where the graph cannot tell callees apart:
a virtual call reaches every override (`SendspinConnection::fail_inbound()`'s close reaches both
transports'), and `esp_event_loop_run()` reaches the library's event handler for every event.

Sizes of what is left out: a second interrupt frame is 192 bytes; ESPHome's logging hook runs
about 100 to 250 bytes deeper than newlib's `vprintf()` chain; ArduinoJson's virtual allocator
chain is about 4.2 KB, under every bound that reaches it, and its nesting costs 64 bytes a level.

## Current figures

Measured on xtensa-esp32 with ESP-IDF 5.5 and GCC 14.2, at `-Os` (ESPHome's default) and `-Og`
(ESP-IDF's default). This table and the `DEFAULT_*_STACK_SIZE` constants in
`include/sendspin/config.h` are updated together.

| Task | Root | Deepest chain | -Os | -Og | Default | Chain ends in |
| --- | --- | --- | --- | --- | --- | --- |
| httpd | `httpd_thread` | esp_http_server's own WebSocket upgrade response (544 to 576 bytes) | 4,032 | 3,968 | 4,608 (`DEFAULT_HTTPD_STACK_SIZE`) | shared ESP-IDF tail |
| websocket client | `esp_websocket_client_task` | library event handler (3,520 / 3,584) closing on a stalled protocol task via `fail_inbound()` through the inbound transport's close | 3,904 | 3,952 | 4,608 (`DEFAULT_WEBSOCKET_STACK_SIZE`) | shared ESP-IDF tail |
| protocol task | task entry | as bounded: an esp_websocket_client send error into the event handler, `handle_data()`, `fail_inbound()` and `httpd_sess_trigger_close` (unreachable); reachable: a pairing confirm dropping an outbound connection whose goodbye send fails (6,352 / 6,576) | 6,560 | 6,832 | 7,168 (`DEFAULT_PROTOCOL_TASK_STACK_SIZE`) | shared ESP-IDF tail |
| source, PCM | `thread_entry()` | `begin_chunk()`'s outbound acquire | 1,104 | 1,168 | 2,048 (`DEFAULT_SOURCE_TASK_STACK_SIZE`) | FreeRTOS critical-section assert |
| source, Opus | `thread_entry()` | the Opus encode, `quant_partition()` charged one pass | 5,152 | 5,168 | 6,656 (`DEFAULT_OPUS_SOURCE_TASK_STACK_SIZE`) | shared ESP-IDF tail |

Notes per task:

- httpd: the task runs no Noise or protocol work. The library's own frame receive
  (`handle_data()` through `httpd_ws_recv_frame()`) is 3,504 / 3,568. 4,032 + 384 = 4,416,
  rounded up.
- websocket client: the close path in the chain is one the graph cannot rule out but no outbound
  connection takes. 3,952 + 384 = 4,336, rounded up.
- protocol task: noise-c and libsodium included. The bounded chain's tail cannot execute (an
  outbound connection never reaches the server connection's close override), so the default is
  sized from the reachable chain: 6,576 + 384 = 6,960, rounded up to 7,168.
- source, PCM: the task sends nothing itself and logs nothing. The `std::thread` entry frames
  above `thread_entry()` are not counted and come out of the rounding slack. 1,168 + 384 = 1,552,
  rounded up.
- source, Opus: `quant_partition()` nests four levels deeper than charged, 576 bytes more, so
  5,168 + 576 = 5,744, + 384 = 6,128, rounded up. The `std::thread` entry frames come out of the
  rounding slack as for PCM.

## Margin and rounding

Every chain except the PCM source task's ends in a shared ESP-IDF tail of about 2.7 KB: an
allocation or lwIP call into an error log line through newlib's `vfprintf` (800 bytes alone), its
lock and an assert, whose last ~500 bytes are a fatal path.

Each default adds 384 bytes to the larger of the two totals: the FreeRTOS exception frame and
coprocessor save area (`XT_STK_FRMSZ` 192: `XtExcFrame` 112, the MAC16 save 48, and 32 for the
interruptee's base save area and nested-function space; `XT_CP_SIZE` 96), and 96 bytes for the
fixed costs outside any frame (`vPortTaskWrapper`'s 32 under `FREERTOS_TASK_FUNCTION_WRAPPER`, the
16-byte overflow canary, 16 of thread-local storage, up to 15 of save-area alignment). The sum is
rounded up to a 512-byte multiple, whose remainder is the only slack.
