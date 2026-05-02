#!/usr/bin/env bash
# Idempotent installer for the project-local verifier toolchain (ADR-0009).
#
# Symlinks the Galois prebuilts, ghcup binaries, opam switch binaries, the
# Python venv, and writes wrapper scripts for the TLA+ jar. Re-run after any
# upstream install to refresh the links.
#
# Prerequisite installs (one-time, see ../README.md "Verifiers" section):
#   - Galois Cryptol/SAW prebuilts under ~/opt/galois/
#   - ghcup with GHC 9.6.7 + cabal 3.10.3.0 under ~/.ghcup/
#   - opam switch "binsec" with binsec, sail, coq under ~/.opam/binsec/
#   - tla2tools.jar under ~/opt/tlaplus/
#   - Python venv at ../venv (created by `python3 -m venv toolchain/venv`)

set -euo pipefail

PROJECT_BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bin"
mkdir -p "$PROJECT_BIN"

ln_if_exists() {
    local src="$1"
    local name="${2:-$(basename "$1")}"
    if [ -e "$src" ]; then
        ln -sf "$src" "$PROJECT_BIN/$name"
    fi
}

# --- Galois: SAW + Cryptol with bundled solvers ------------------------------
SAW_ROOT="$HOME/opt/galois/saw-1.5-macos-15-ARM64-with-solvers"
CRY_ROOT="$HOME/opt/galois/cryptol-3.5.0-macos-15-ARM64-with-solvers"

for tool in saw saw-remote-api crux-mir-comp; do
    ln_if_exists "$SAW_ROOT/bin/$tool"
done
# Solvers (SAW's bundle is a strict superset of Cryptol's).
for tool in z3 cvc4 cvc5 yices yices-smt2 abc bitwuzla boolector; do
    ln_if_exists "$SAW_ROOT/bin/$tool"
done
for tool in cryptol cryptol-eval-server cryptol-html cryptol-language-server cryptol-remote-api; do
    ln_if_exists "$CRY_ROOT/bin/$tool"
done

# --- GHC + cabal (ghcup) -----------------------------------------------------
for tool in ghc ghc-9.6.7 ghci ghc-pkg cabal cabal-install ghcup runghc runhaskell; do
    ln_if_exists "$HOME/.ghcup/bin/$tool"
done

# --- opam: binsec, sail, coq -------------------------------------------------
OPAM_BIN="$HOME/.opam/binsec/bin"
for tool in opam ocaml binsec sail sail_maker coqc coqchk coqdep coqdoc coqmakefile coqnative coqpp coqtop coqwc coq-tex rocq; do
    ln_if_exists "$OPAM_BIN/$tool"
done
# opam itself usually lives under brew, link from there if not in switch.
[ ! -e "$PROJECT_BIN/opam" ] && ln_if_exists /opt/homebrew/bin/opam

# --- Python venv (angr) ------------------------------------------------------
VENV="$(cd "$PROJECT_BIN/.." && pwd)/../venv"
ln_if_exists "$VENV/bin/python" venv-python

# --- TLA+ tools wrapper scripts ----------------------------------------------
TLA_JAR="$HOME/opt/tlaplus/tla2tools.jar"
if [ -e "$TLA_JAR" ]; then
    cat > "$PROJECT_BIN/tlc" <<EOF
#!/usr/bin/env bash
exec java -XX:+UseParallelGC -cp "$TLA_JAR" tlc2.TLC "\$@"
EOF
    cat > "$PROJECT_BIN/tla2sany" <<EOF
#!/usr/bin/env bash
exec java -cp "$TLA_JAR" tla2sany.SANY "\$@"
EOF
    chmod +x "$PROJECT_BIN/tlc" "$PROJECT_BIN/tla2sany"
fi

echo "toolchain/local/bin populated:"
ls "$PROJECT_BIN" | sort
