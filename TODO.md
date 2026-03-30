# TODO

## Improvements

- [x] Redesign queued events in the loop function to be more embedded friendly
- [ ] Standardize the API
- [ ] ArtworkRole `on_image` fires directly from the network thread for received images but from the main thread for clears — either defer image data through a queue like other roles or document the split threading contract clearly
- [ ] Wrap the `on_image` callback's 5 positional parameters in a struct (like `VisualizerFrame`)
- [x] Ensure connection is fully torn down (no more callbacks) before cleanup runs to prevent stale events from a dead connection sneaking into role queues

## Known Issues

- [x] Host examples sometimes play static (fixed by pausing and resuming)
- [ ] Audio sync can be inaccurate during rapid restarts due to a bug in the PortAudio adapter
- [x] TUI visualizer seems to get out of sync over time
