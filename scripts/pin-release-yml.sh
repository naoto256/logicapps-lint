#!/usr/bin/env bash
# Harden the cargo-dist release workflow after `dist generate`:
#
#   1. Rewrite every `uses: <action>@<tag>` line to an audited full SHA plus a
#      `# pin-audit:<date> <short> | <tag>` comment.
#   2. Narrow the top-level `permissions` block from `contents: write` — which
#      cargo-dist emits by default — down to `contents: read`, and inject
#      `permissions: { contents: write }` on the `host` job so that only the
#      GitHub-Release step keeps write access.
#   3. Replace the `curl …/cargo-dist-installer.sh | sh` bootstrap with a
#      `cargo install cargo-dist --version <pin> --locked` step so the runner
#      never fetches an unverified shell script.
#   4. Delete the rustup `curl … | sh` block on the container-only path when
#      the current `dist plan` output shows no matrix entry with a container.
#      If a container reappears, refuse to strip the block — the operator must
#      restore rustup or (better) pin a container image with Rust pre-installed.
#
# The script exits non-zero when it encounters an unknown action, an unknown
# tag, a permission block whose shape does not match cargo-dist's current
# output, or an unexpected matrix.container — a silent upstream layout change
# must never slip through unnoticed. Update the mapping (and
# `audited-pins.md`) before allowing the pin.

set -euo pipefail

WORKFLOW="${1:-.github/workflows/release.yml}"

if [[ ! -f "$WORKFLOW" ]]; then
    echo "pin-release-yml: workflow not found: $WORKFLOW" >&2
    exit 2
fi

# Mapping: each entry pipes into ref|full-sha|short-sha|audit-date|version.
# Each entry must correspond to a row in
# .claude/skills/uchgs-audit/scope/cicd-pipeline/audited-pins.md that is
# currently Pass. Deletions here require a paired audited-pins.md update.
MAPPING=(
    "actions/checkout@v6|de0fac2e4500dabe0009e67214ff5f5447ce83dd|de0fac2|2026-06-03|v6.0.2"
    "actions/upload-artifact@v7|043fb46d1a93c77aae656e7c1c64a875d1fc6a0a|043fb46|2026-07-11|v7.0.1"
    "actions/download-artifact@v8|3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c|3e5f45b|2026-07-11|v8.0.1"
)

expected_count="${#MAPPING[@]}"

# Collect unique action@tag references from the workflow (portable to bash 3.2).
unique_refs="$(grep -E '^[[:space:]]*(- )?uses:' "$WORKFLOW" \
    | sed -E 's/.*uses:[[:space:]]*([^[:space:]#]+).*/\1/' \
    | sort -u)"

unknown=0
tag_refs=""
while IFS= read -r ref; do
    [[ -z "$ref" ]] && continue
    # Already-pinned lines carry a 40-char full SHA; skip so the script stays
    # idempotent for re-runs.
    tag="${ref#*@}"
    if [[ "$tag" =~ ^[0-9a-f]{40}$ ]]; then
        continue
    fi
    found=0
    for row in "${MAPPING[@]}"; do
        if [[ "$ref" == "${row%%|*}" ]]; then
            found=1
            break
        fi
    done
    if [[ $found -eq 0 ]]; then
        echo "pin-release-yml: unaudited uses: $ref" >&2
        unknown=1
    fi
    tag_refs="${tag_refs}${ref}"$'\n'
done <<<"$unique_refs"

if [[ $unknown -ne 0 ]]; then
    echo "pin-release-yml: refuse to pin an unknown action; update MAPPING and audited-pins.md" >&2
    exit 3
fi

actual_unique="$(printf '%s' "$tag_refs" | sed '/^$/d' | wc -l | tr -d '[:space:]')"
if [[ "$actual_unique" -ne "$expected_count" && "$actual_unique" -ne 0 ]]; then
    echo "pin-release-yml: expected $expected_count unique tag refs, found $actual_unique" >&2
    exit 4
fi

# Apply substitutions using Perl. The MAPPING key format `owner/repo@tag`
# never contains regex metacharacters beyond `/`, so quotemeta handles it.
# When actual_unique is 0 every ref is already a SHA — the substitution loop
# is a no-op and we fall through to the remaining shape checks so an
# idempotent rerun still catches regressions in permissions / bootstrap /
# rustup guards.
if [[ "$actual_unique" -gt 0 ]]; then
    for row in "${MAPPING[@]}"; do
        IFS='|' read -r ref sha short date version <<<"$row"
        action="${ref%@*}"
        export _REF="$ref" _ACT="$action" _SHA="$sha" _DATE="$date" _SHORT="$short" _VER="$version"
        perl -i -pe '
            my $ref = quotemeta $ENV{_REF};
            s{^(\s*(?:-\s+)?uses:\s*)$ref(\s*)$}{$1$ENV{_ACT}\@$ENV{_SHA} # pin-audit:$ENV{_DATE} $ENV{_SHORT} | $ENV{_VER}\n};
        ' "$WORKFLOW"
    done
    echo "pin-release-yml: pinned $expected_count unique action reference(s) in $WORKFLOW"
else
    echo "pin-release-yml: uses: refs already pinned (still enforcing invariants)"
fi

# Narrow the top-level `permissions:` block. cargo-dist emits exactly
# `permissions:\n  "contents": "write"\n` today; any deviation is a red flag.
# On idempotent reruns the block already reads `contents: read` and we must
# still confirm it did not drift back to `write`.
if ! grep -qE '^permissions:$' "$WORKFLOW"; then
    echo "pin-release-yml: expected a top-level 'permissions:' block" >&2
    exit 5
fi
if grep -qE '^  "contents": "write"$' "$WORKFLOW"; then
    perl -i -0pe '
        s{
            (^permissions:\n)
            (\ \ "contents":\ "write"\n)
        }{$1  "contents": "read"\n}mx
    ' "$WORKFLOW"
elif ! grep -qE '^  "contents": "read"$' "$WORKFLOW"; then
    echo "pin-release-yml: unexpected top-level permissions shape (neither 'write' nor 'read')" >&2
    exit 6
fi

# Grant `contents: write` to the host job only, immediately under `runs-on:`.
# Skip on the second run (already injected — line reads `contents: write`).
if grep -qE '^      contents: write$' "$WORKFLOW"; then
    :
else
    tmpfile="$(mktemp)"
    perl -0pe '
        my $ok = s{^  host:\n((?:[^\n]*\n)*?)    runs-on: "ubuntu-22\.04"\n}
                  {qq(  host:\n${1}    runs-on: "ubuntu-22.04"\n    permissions:\n      contents: write\n)}mse;
        exit(9) unless $ok;
    ' "$WORKFLOW" > "$tmpfile"
    if [[ ! -s "$tmpfile" ]]; then
        rm -f "$tmpfile"
        echo "pin-release-yml: failed to inject host-job permissions" >&2
        exit 7
    fi
    mv "$tmpfile" "$WORKFLOW"
fi

echo "pin-release-yml: hardened top-level permissions and host-job overrides"

# Replace the `curl … cargo-dist-installer.sh | sh` bootstrap. The version
# below MUST match `cargo-dist-version` in dist-workspace.toml so plan runs
# against the same generator that produced the workflow.
CARGO_DIST_VERSION="0.32.0"
if grep -qF "cargo-dist/releases/download/v${CARGO_DIST_VERSION}/cargo-dist-installer.sh" "$WORKFLOW"; then
    perl -i -pe '
        s{curl --proto '"'"'=https'"'"' --tlsv1\.2 -LsSf https://github\.com/axodotdev/cargo-dist/releases/download/v'"${CARGO_DIST_VERSION}"'/cargo-dist-installer\.sh \| sh}
         {cargo install cargo-dist --version '"${CARGO_DIST_VERSION}"' --locked}g;
    ' "$WORKFLOW"
    # The generator emits a two-line comment justifying `shell: bash` (pipefail
    # for the curl|sh pipeline). Once the pipeline is gone the note is stale;
    # drop the comment and the `shell: bash` line so the step reads clean.
    tmpfile="$(mktemp)"
    perl -0pe '
        s{
            \n[ ]{8}\#\ we\ specify\ bash\ to\ get\ pipefail;\ it\ guards\ against\ the\ `curl`\ command\n
            [ ]{8}\#\ failing\.\ otherwise\ `sh`\ won.t\ catch\ that\ `curl`\ returned\ non-0\n
            [ ]{8}shell:\ bash\n
        }{\n}sx;
    ' "$WORKFLOW" > "$tmpfile"
    if [[ -s "$tmpfile" ]]; then
        mv "$tmpfile" "$WORKFLOW"
    else
        rm -f "$tmpfile"
    fi
    echo "pin-release-yml: replaced cargo-dist curl|sh with cargo install --locked pin"
elif ! grep -qF "cargo install cargo-dist --version ${CARGO_DIST_VERSION} --locked" "$WORKFLOW"; then
    echo "pin-release-yml: neither the pinned cargo-dist installer nor the expected cargo-install line was found" >&2
    exit 8
fi

# From this point downward the rustup guard runs whether or not the workflow
# was already hardened — the invariant "matrix has no container entries" must
# be re-checked on every hardening pass, so `dist` and `jq` are hard
# requirements, not "warn and continue".

# Strip the rustup `curl | sh` block on the container-only path when the
# current dist plan has no container entries. If a container appears we bail
# so the operator has to make an informed decision.
if ! command -v dist >/dev/null 2>&1; then
    echo "pin-release-yml: 'dist' is required to verify the matrix has no container entries" >&2
    exit 11
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "pin-release-yml: 'jq' is required to parse the dist plan matrix" >&2
    exit 12
fi

tmp_plan="$(mktemp)"
if ! dist plan --output-format=json --allow-dirty > "$tmp_plan" 2>/dev/null; then
    rm -f "$tmp_plan"
    echo "pin-release-yml: dist plan failed; refusing to strip rustup block without a fresh matrix" >&2
    exit 9
fi
containers="$(jq -r '.ci.github.artifacts_matrix.include | map(.container // "none") | unique | @csv' "$tmp_plan")"
rm -f "$tmp_plan"
if [[ "$containers" != '"none"' ]]; then
    echo "pin-release-yml: dist plan matrix contains container entries ($containers); refusing to strip rustup block" >&2
    exit 10
fi

# No container in the matrix — strip the rustup block if it is still present.
tmpfile="$(mktemp)"
perl -0pe '
    s{
        [ ]{6}-[ ]name:\ Install\ Rust\ non-interactively\ if\ not\ already\ installed\n
        [ ]{8}if:\ \$\{\{\ matrix\.container\ \}\}\n
        [ ]{8}run:\ \|\n
        (?:[ ]{10}[^\n]*\n)+
    }{}sx;
' "$WORKFLOW" > "$tmpfile"
if [[ -s "$tmpfile" ]]; then
    mv "$tmpfile" "$WORKFLOW"
fi
if grep -qF "Install Rust non-interactively if not already installed" "$WORKFLOW"; then
    echo "pin-release-yml: rustup 'Install Rust non-interactively' step still present after strip" >&2
    exit 13
fi
echo "pin-release-yml: verified no rustup container fallback (matrix has no container entries)"

# Guard the Homebrew tap-publish job with an explicit publishing check so its
# `HOMEBREW_TAP_TOKEN` read does not depend on the `host` job being skipped
# elsewhere. cargo-dist ships the prerelease-only guard by default; we add the
# publishing predicate in front of it so PR runs never even evaluate the tap
# checkout step.
publish_guard_expected='    if: ${{ needs.plan.outputs.publishing == '\''true'\'' && (!fromJson(needs.plan.outputs.val).announcement_is_prerelease || fromJson(needs.plan.outputs.val).publish_prereleases) }}'
publish_guard_default='    if: ${{ !fromJson(needs.plan.outputs.val).announcement_is_prerelease || fromJson(needs.plan.outputs.val).publish_prereleases }}'
if grep -qxF "$publish_guard_default" "$WORKFLOW"; then
    tmpfile="$(mktemp)"
    awk -v want="$publish_guard_expected" -v have="$publish_guard_default" \
        '{ if ($0 == have) print want; else print }' \
        "$WORKFLOW" > "$tmpfile"
    mv "$tmpfile" "$WORKFLOW"
elif ! grep -qxF "$publish_guard_expected" "$WORKFLOW"; then
    echo "pin-release-yml: publish-homebrew-formula 'if:' shape does not match either default or hardened form" >&2
    exit 14
fi
echo "pin-release-yml: publish-homebrew-formula guarded on plan.outputs.publishing"

# Refuse to accept the raw cargo-dist output that interpolates
# `github.ref_name` (or the `tag-flag` derived from it) into shell commands.
# The hardened workflow feeds the tag through an env var and uses "$DIST_TAG"
# inside a shell if/else, so an attacker-controlled ref name cannot escape the
# quoting. See CodeRabbit finding on release.yml:77 (template-injection).
if grep -qE "dist \\\$\\{\\{[^}]*github\\.ref_name[^}]*\\}\\}" "$WORKFLOW"; then
    echo "pin-release-yml: unhardened dist <run> line still interpolates github.ref_name; re-apply the DIST_TAG env-var hardening" >&2
    exit 15
fi
if grep -qE "dist (build|host) \\\$\\{\\{ needs\\.plan\\.outputs\\.tag-flag \\}\\}" "$WORKFLOW"; then
    echo "pin-release-yml: dist build/host still uses raw tag-flag interpolation; switch to env DIST_TAG + shell quoting" >&2
    exit 16
fi
if grep -qE "gh release create \"\\\$\\{\\{ needs\\.plan\\.outputs\\.tag \\}\\}\"" "$WORKFLOW"; then
    echo "pin-release-yml: gh release create still interpolates plan.outputs.tag; switch to env DIST_TAG" >&2
    exit 17
fi
echo "pin-release-yml: verified shell commands do not interpolate ref_name / tag-flag"

# The `Build artifacts` step in the local-build matrix runs on Windows too,
# where the default shell is PowerShell and refuses to parse `if [ … ]; then`.
# Ensure `shell: bash` is set so the hardened DIST_TAG conditional works
# uniformly across ubuntu/macos/windows runners.
if perl -0ne '
    exit 1 if /- name: Build artifacts\n(?![ ]{8}shell: bash\n)/;
' "$WORKFLOW"; then
    :
else
    echo "pin-release-yml: 'Build artifacts' step is missing 'shell: bash'; PowerShell will reject the DIST_TAG conditional on Windows" >&2
    exit 18
fi
echo "pin-release-yml: verified Build artifacts step forces shell: bash"
