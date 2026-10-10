# DelayedSingleton shared_ptr race: isolated TSan reproduction

Status: local, isolated WSL2 dynamic evidence only. This is not an exploit and
not a full vulnerability verdict. It records one narrow harness outcome on two
pinned OpenHarmony commits.

## Pinned inputs

| Role | Commit | Affected file | Source SHA-256 |
|---|---|---|---|
| vulnerable | `bdfafdaafddb01ab7ae13354ce2ada9555d7935c` | `base/include/singleton.h` | `ce04ace5a2ad702d3f56e30be347dc9583c808dcf5aac80ee761bd70e05f1ad4` |
| fixed | `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7` | `base/include/singleton.h` | `9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606` |
| header | both commits | `base/include/nocopyable.h` | `388f5c506f925f6f4fbe00e9937c4ff2550a65a4058a57fe110f54735579a30e` |

Self-authored harness source is tracked at
`research/experiments/cpp/shared_ptr_race_tsan/harness.cpp`:

`cb190005bda9e46fa12d61ee262880e9d0bba32cc05779bf98ba36a401f6a630`

OpenHarmony source bytes are fetched in a temporary directory from the pinned
commit and are not committed to this repository.

## Environment

- WSL2 Ubuntu 22.04.1 host kernel
  `6.18.40.1-microsoft-standard-WSL2`
- `clang++` Ubuntu clang version 14.0.0-1ubuntu1.1
- `g++` Ubuntu 11.4.0 was present, but the final run used clang 14 TSan
- ThreadSanitizer required `setarch $(uname -m) -R` under WSL2 to avoid
  `ThreadSanitizer: unexpected memory mapping`.

## Isolated build and run commands

From WSL, clone/fetch only the two pinned commits into a temporary directory:

```bash
BASE=/tmp/ohscanner_shared_ptr_race_tsan
rm -rf "$BASE"; mkdir -p "$BASE"/{vuln,fixed,logs}
rm -rf /tmp/cutils_repo; mkdir /tmp/cutils_repo; cd /tmp/cutils_repo
git clone --no-checkout https://github.com/openharmony/commonlibrary_c_utils.git .
git fetch origin \
  bdfafdaafddb01ab7ae13354ce2ada9555d7935c \
  9a3f281120307ec7dcce17fae882dcc4e6a6f4d7

git show bdfafdaafddb01ab7ae13354ce2ada9555d7935c:base/include/singleton.h \
  > "$BASE/vuln/singleton.h"
git show bdfafdaafddb01ab7ae13354ce2ada9555d7935c:base/include/nocopyable.h \
  > "$BASE/vuln/nocopyable.h"
git show 9a3f281120307ec7dcce17fae882dcc4e6a6f4d7:base/include/singleton.h \
  > "$BASE/fixed/singleton.h"
git show 9a3f281120307ec7dcce17fae882dcc4e6a6f4d7:base/include/nocopyable.h \
  > "$BASE/fixed/nocopyable.h"
```

Copy the tracked harness and build each revision:

```bash
cp research/experiments/cpp/shared_ptr_race_tsan/harness.cpp \
  "$BASE/vuln/harness.cpp"
cp research/experiments/cpp/shared_ptr_race_tsan/harness.cpp \
  "$BASE/fixed/harness.cpp"

cd "$BASE/vuln"
clang++ -std=c++17 -fsanitize=thread -O1 -g -pthread -I. \
  harness.cpp -o vuln_harness

cd "$BASE/fixed"
clang++ -std=c++17 -fsanitize=thread -O1 -g -pthread -I. \
  harness.cpp -o fixed_harness
```

Run under TSan:

```bash
cd "$BASE/vuln"
TSAN_OPTIONS="halt_on_error=0:exitcode=66:history_size=7" \
  setarch $(uname -m) -R ./vuln_harness

cd "$BASE/fixed"
TSAN_OPTIONS="halt_on_error=0:exitcode=66:history_size=7" \
  setarch $(uname -m) -R ./fixed_harness
```

## Recorded observations

| Revision | Build wall-clock | Build max RSS | Run wall-clock | Run max RSS | Exit code |
|---|---:|---:|---:|---:|---:|
| vulnerable | 1.05 s | 121,772 KB | 0.65 s | 29,612 KB | 66 |
| fixed | 0.75 s | 121,808 KB | 0.51 s | 25,268 KB | 0 |

The `/usr/bin/time` output files are preserved under
`outputs/logs/shared_ptr_race_tsan/logs/*.time`.

### Vulnerable TSan evidence

`vuln_tsan.log` contains ThreadSanitizer reports including:

- data race on global `OHOS::DelayedSingleton<Payload>::instance_`;
- write path through `DestroyInstance()` / `instance_.reset()` at
  `singleton.h:141`;
- read path through `GetInstance()` / `instance_ == nullptr` at
  `singleton.h:125` and `return instance_` at `singleton.h:133`;
- heap-use-after-free read in the harness at `harness.cpp:31`.

Run log SHA-256:

`60e20013521be5afb81b1e7634f76f897182d2d913de4fbc01eb93d12e7c9377`

### Fixed no-trigger observation

`fixed_tsan.log` is empty and the process exits 0. This is not a proof of
safety; it only records that this harness/commit/environment run produced no
TSan report.

## Detector integration note

`ohscanner.cpp.shared_ptr_race` is a separate static detector; it does not run
this harness and does not consume the TSan log. On the exact `singleton.h`
source text, it observes the narrow non-atomic `shared_ptr` shape in the
vulnerable revision and no candidate in the fixed revision. The TSan run is
independent dynamic evidence and does not upgrade a detector finding by itself.

The deterministic source-hash-bound static evidence can be regenerated from
origin-verified exact Git tree/blob objects with
`research/experiments/cpp/shared_ptr_race_native_evidence.py`. A separately
pinned binding manifest fixes the vulnerable/fixed commits, tree/blob IDs and
source SHA-256 values; arbitrary exported files cannot claim `git_object`
provenance. Generated JSON/Markdown are kept under ignored
`outputs/reports/shared_ptr_race_native/`.
