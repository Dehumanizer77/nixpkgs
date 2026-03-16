# Review: branch ahead by 4 commits

## Scope and methodology

- Intended comparison target: `NixOS/nixpkgs:master` vs `Dehumanizer77/nixpkgs:wazuh-agent-clean`.
- Network access to GitHub was blocked in this environment (`CONNECT tunnel failed, response 403`), so I reviewed the top 4 local commits on the current branch, which match the requested "4 commits ahead" shape.
- Reviewed each commit diff for packaging correctness, dependency semantics, metadata consistency, and likely Nixpkgs policy alignment.

## Commit-by-commit review

### 1) `38bf94b3d7de` — `xash3d-fwgs: init at 0-unstable-2026-02-25`

**Files:**
- `pkgs/by-name/hl/hlsdk-portable/package.nix` (new)
- `pkgs/by-name/xa/xash3d-fwgs/package.nix` (new)
- `pkgs/top-level/all-packages.nix`

**Positive findings**
- Good split of reusable SDK (`hlsdk-portable`) and engine package (`xash3d-fwgs`).
- Variant support is clear and idiomatic (`buildServer`, `buildSdk`).
- Runtime wrapper handles engine resource/library paths cleanly.

**Issues found**
1. **High** — `platforms = lib.platforms.all` likely overbroad for both new packages.
   - `xash3d-fwgs` conditionally links X11/SDL/audio stacks and is likely not valid on all nixpkgs platforms (e.g. many embedded/non-ELF targets).
   - `hlsdk-portable` is also declared as `all` without evidence the waf project supports all targets.
   - Recommendation: narrow to tested targets (likely Linux/Darwin, maybe subset).

2. **Medium** — `hlsdk-portable` is introduced but not surfaced as a top-level attr explicitly.
   - This may be intentional with by-name infra, but if discoverability was intended, add alias/entry or document expected access path in commit message.

### 2) `dcae2fed71ed` — `beans: 0.4.0 -> 0.4.2`

**Files:**
- `pkgs/by-name/be/beans/package.nix`

**Positive findings**
- Straightforward version/hash bump.
- No suspicious dependency or build-system changes.

**Issues found**
- **None** from static review.

### 3) `ec001930650e` — `python3Packages.devito: 4.8.20 -> 4.8.21`

**Files:**
- `pkgs/development/python-modules/devito/default.nix`
- `pkgs/development/python-modules/devito/fix-codepy-compat.patch` (new)

**Positive findings**
- Correctly adds a compatibility patch for `codepy >= 2025.1` API/behavior changes.
- Patch intent is well documented inline.
- Added targeted test skip with rationale for precision instability.

**Issues found**
1. **Medium** — compatibility patch bypasses upstream base-class initialization semantics.
   - The patch overrides frozen dataclass attribute restrictions and skips `GCCToolchain.__init__`, manually setting only selected fields (`o_ext`, `features`).
   - This is pragmatic but brittle if `codepy` adds new required fields/behavior.
   - Recommendation: add an upstream link in comments and track removal criteria; consider follow-up to fully initialize required fields defensively.

### 4) `6a7f1a34047f` — `libretro.mame2003-plus: 0-unstable-2026-02-27 -> 0-unstable-2026-03-10`

**Files:**
- `pkgs/applications/emulators/libretro/cores/mame2003-plus.nix`

**Positive findings**
- Clean bump of rev/version/hash only.

**Issues found**
- **None** from static review.

## Overall assessment

- **Result:** Mostly good with one actionable correctness concern and one maintainability concern.
- **Blocking concern before merge:** overly broad `platforms = lib.platforms.all` on the new Xash/HL SDK packages.
- **Non-blocking follow-up:** make the devito `codepy` compatibility patch less fragile or annotate with a clearer upstream tracking reference.

## Validation attempted

- `git log --oneline --decorate -n 12`
- `git diff <parent> <merge-commit>` for each of the 4 commits
- `nix-instantiate --eval -E 'with import ./. {}; beans.version'` (could not run: nix tooling unavailable in container)
