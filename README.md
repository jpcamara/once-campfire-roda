# Campfire on Roda

[Campfire](https://github.com/basecamp/once-campfire) reimplemented on Roda and Sequel, running on
Falcon. It runs on the Rails app's SQLite schema, storage layout and frontend assets unchanged, and
keeps its signed and encrypted cookies compatible, so sessions carry over. From the outside it
behaves like the Rails app. That's checked with the Playwright parity harness from DHH's
[once-campfire-rust](https://github.com/basecamp/once-campfire-rust).

It's one of four Ruby implementations benchmarked together. The benchmark notes, harness changes,
per-change measurements and raw results are on the
[`benchmarks` branch](https://github.com/jpcamara/once-campfire-sinatra/tree/benchmarks) of the
Sinatra repo.

| Implementation | Code |
|---|---|
| Rails, optimized | [jpcamara/once-campfire, branch `perf`](https://github.com/jpcamara/once-campfire/tree/perf) |
| Sinatra + Falcon | [jpcamara/once-campfire-sinatra](https://github.com/jpcamara/once-campfire-sinatra) |
| Rage + Sequel | [jpcamara/once-campfire-rage](https://github.com/jpcamara/once-campfire-rage) |
| Roda + Sequel (Falcon) | this repo |

## Design

Roda + Sequel is Jeremy Evans' own pairing. It runs on the same server as the Sinatra app (Falcon) and
uses the same data-layer library as the Rage app (Sequel), so each comparison isolates one layer.

- **Web:** a Roda routing tree on Falcon, one forked process per CPU. Plugins: `all_verbs`, `head`,
  `cookies`, plus `Rack::MethodOverride` for forms that send `_method`. The app is frozen after boot.
- **Routes:** one handler method per route, dispatched from a tree grouped by first segment
  (`rooms`, `account`, `users`, `messages`, `session`, `searches`, `rails/active_storage`). Paths
  match whole, and within a branch the first match wins, so rooms#show's any-segment catch-all
  comes last.
- **Responses:** a small plugin finishes responses the way the handlers expect. A handler's value is
  the body, Content-Type defaults to `text/html`, 204 and 304 carry no body, and Content-Length is
  counted for string bodies.
- **Database:** Sequel over SQLite (WAL, `synchronous=NORMAL`). Each process has one reader and one
  writer connection: a single-threaded Sequel database with two shards. Every query is a prepared
  statement, run by name. The writer waits with the sqlite3 gem's own busy handler.
- **Shared code:** the views (the reference's ERB, ported to Erubi), Rails-compatible cookies and
  signing, rich text, attachments, storage, Action Cable and compression are the Sinatra app's,
  file for file. Only `lib/campfire/app.rb` (Roda) and `lib/campfire/db.rb` (Sequel) differ.
- **Action Cable** runs on `async-websocket`, with Redis pub/sub between processes. Jobs run
  in-process, as in the Rust port.

## Performance

*Final numbers are being measured; this section will carry them.*

## Caching and optimizations

The rule: every optimization is one of these.
1. A fix of our own bug or misconfiguration.
2. Something the Rust port does, cited in once-campfire-rust.
3. A cache with Elixir-port precedent that was approved: the read cache, the kept sidebar, the
   per-ETag messages page, and the room/search shell memo.

| What | Category | Precedent |
|---|---|---|
| Byte-offset page splitting; random-token fragment markers | (1) | fixes in the shared code |
| Compressed pieces: each fragment's deflate block, and the text between | (2) | Rust `crates/kit/src/deflater/splice.rs` |
| Whole-body gzip kept by digest | (2) | Rust 2f755bf |
| Page ETags from page parts; cookies only when they change; `Sec-Fetch-Site` CSRF | (2) | Rust 2947c64, 2f755bf, b567772 |
| Public-response cache (avatars, assets) | (2) | Rust `crates/kit/src/front/cache.rs` |
| Prepared statements | (2) | Rust `crates/db/src/database.rs` |
| WAL checkpoints in their own process | (2) | Rust `crates/db/src/database.rs` (checkpointer thread) |
| Read cache cleared on `PRAGMA data_version` | (3) | Elixir `lib/campfire/db.ex` |
| Finished sidebar until its data changes | (3) | Elixir `lib/campfire/sidebar.ex` |
| Messages page parts per ETag | (3) | Elixir `lib/campfire/messages.ex` |
| Room and search shell memoized by inputs | (3) | Elixir `lib/campfire/room_page.ex`, `searches.ex` |
| Remembered verified `session_token` signature | kept, as in Sinatra and Rage | Elixir `lib/campfire/auth.ex` |

`CAMPFIRE_CACHING=rust` turns off the Elixir-only caches, leaving only what Rust caches.

Not included, because Rust doesn't do them:
- a plain-text fast path that skipped the rich-text pipeline
- a 100 µs busy-handler retry
- one Redis PUBLISH per post
- building a new post's view from request data
- memoized tokens, signed ids and initials

## Differences from Rails

Only the ones the Rust port documents in its README under "Known differences":
- `Sec-Fetch-Site` replaces CSRF tokens (with the Rust port's `file_uploader.js` override).
- Jobs run in-process.
- Cookies are written only when they change.
- Page ETags come from what a page is made of.

One more: the public-response cache is per worker process, so a repeat request that reaches another
worker says `X-Cache: miss` where Thruster says `hit`. That's the same as Sinatra and Rage.

## Status

*Final parity and security results are being collected; this section will carry them.*

## Running it

It needs the reference image `campfire-reference:app`, built with `parity/bin/reference build` in
once-campfire-rust, for the digested assets.

```sh
docker build -t campfire-roda:app .
docker run -p 3000:80 --env-file path/to/once-campfire-rust/parity/.env.reference \
  -v $PWD/storage/db:/rails/storage/db -v $PWD/storage/files:/rails/storage/files campfire-roda:app
```

For local development, `bin/dev [PORT]` runs it against `STORAGE_PATH` (a copy of the parity seed),
with once-campfire-rust checked out next to this repo.
