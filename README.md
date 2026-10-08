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

Final run, Oct 8 2026, on the code after the precedent audit (image built from 44c135c). It used DHH's
`bench/run` on a Hetzner Ryzen 7 PRO 8700GE. Each app gets four hardware threads, with the load
generator on four others. YJIT and jemalloc are on. Each number is the median of 3 runs in rotating
order, with stock Rails, Sinatra, Rage and DHH's Rust port in the same session. There were 0 errors.

| HTTP workload (requests/sec, 16 clients) | Rails (stock) | Sinatra | Rage | **Roda** | Rust |
|---|---:|---:|---:|---:|---:|
| Room page | 222 | 11,303 | 10,146 | **12,431** | 21,206 |
| Messages page | 362 | 16,197 | 24,784 | **19,386** | 23,634 |
| Sidebar | 467 | 22,533 | 33,989 | **27,366** | 20,652 |
| Search | 372 | 14,574 | 16,843 | **16,294** | 21,361 |
| Post a message | 197 | 1,851 | 1,639 | **1,732** | 4,122 |
| Avatar | 62,119 | 73,951 | 178,931 | **75,871** | 196,130 |

| Other | Rails (stock) | Sinatra | Rage | **Roda** | Rust |
|---|---:|---:|---:|---:|---:|
| Action Cable, 1,000 clients: p50 delivery | 42.0 ms | 8.1 ms | 5.0 ms | **7.9 ms** | 4.0 ms |
| Action Cable, 1,000 clients: saturated delivery | 12 msg/s | 98 msg/s | 190 msg/s | **104 msg/s** | 377 msg/s |
| Upload + thumbnail (505 KB) | 87 ms | 59 ms | 134 ms | **131 ms** | 35 ms |
| Idle memory (anon) | 282 MB | 199 MB | 170 MB | **196 MB** | 13 MB |
| Cold start | 3.6 s | 1.5 s | 1.6 s | **1.4 s** | 0.3 s |

In every Action Cable run, every client got every message.

- **Against Sinatra:** the two apps share every file except the web layer (`app.rb`) and the database
  layer (`db.rb`), and run on the same server. So the gap is Roda + Sequel against Sinatra + the
  sqlite3 gem. Roda reads 10–21% faster on every page route. It posts 6% slower.
- **Against Rage:** the two share Sequel and the view code, but not the server. Rage leads on the
  messages page, the sidebar, avatars and Action Cable, where Iodine's C layer does the work.
- **Uploads are noisy between runs.** Sinatra measured 135 ms in an earlier run and 59 ms in this one.
  The cause hasn't been found.

**Room-page reads while posts arrive** (reads/sec at 16 clients while another user posts into the
same room; median of 3 reps, each on a fresh seed, every post at the offered rate, 0 errors). Roda's
row is its own run. The other rows are from the Oct 8 final mixed run on the same box, on the same
code as above (stock Rails and Rust from Oct 7; their code didn't change):

| Posts/sec in the background | 0 | 20 | 100 | Post p50 at 100/s |
|---|---:|---:|---:|---:|
| Rails (stock) | 228 | 214 | 194 | 9.9 ms |
| Sinatra | 11,253 | 10,806 | 7,748 | 3.1 ms |
| Rage | 10,100 | 9,361 | 6,558 | 3.6 ms |
| **Roda** | **12,282** | **11,124** | **7,686** | **3.2 ms** |
| Rust | 20,968 | 20,526 | 19,156 | 2.2 ms |

**Rust-level caching only** (`CAMPFIRE_CACHING=rust`: the Elixir-only caches off, Rust's kept). Same box
and harness, 3 runs, HTTP suite, 0 errors:

| Workload (req/s, 16 clients) | Full caching | Rust-level caching only | Rust |
|---|---:|---:|---:|
| Room page | 12,431 | 5,037 | 21,206 |
| Messages page | 19,386 | 8,413 | 23,634 |
| Sidebar | 27,366 | 6,448 | 20,652 |
| Search | 16,294 | 7,269 | 21,361 |
| Post a message | 1,732 | 1,676 | 4,122 |

With Rust's caching alone, Roda reads at 24–36% of Rust's rate and posts at 41% of it.

**Hardware.** This box is slower than DHH's: Rust runs at about 60% of his published numbers here,
and stock Rails at about 90% of his on reads. So his table overstates the Ruby-to-Rust gap by about
1.5×.

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

- **Parity:** on the final image, the Playwright harness passes every cell on every seed, with no
  allowed differences:

  | Seed | Cells passing |
  |---|---:|
  | default | 874 / 874 |
  | crowd | 25 / 25 |
  | custom_styles | 33 / 33 |
  | first_run | 16 / 16 |
  | restricted | 8 / 8 |

- **Server HTML:** 64 pages match the reference on a fresh pass and a cached pass, and all 24 write
  flows give the same status and redirect.
- **Cache check mode:** 0 mismatches across posts and a rename from 4 processes.
- **Security:** the audit's fix checks pass, 28 of 28. They cover:
  - stored XSS through uploads
  - the `/cable` Origin rules
  - forgery rules, including cookie-authenticated bot writes
  - fragment-marker injection
  - HTTPS headers
  - private-IP bans
  - boost length
  - `X-Request-Id`

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
