#!/bin/sh
set -eu

root=${1:?vcpkg root is required}
baseline=${2:?vcpkg baseline is required}
archive_sha256=${3:?vcpkg archive SHA-256 is required}
deadline_at=${4:?job deadline is required}

case "$baseline:$archive_sha256" in
  1004d5d0f80ac648514e3e6ce8e033f44b45e246:cd84579f7dc9b4be03504c04658470f2e9b65260640962731faa4cc2fe504897|\
  cea592f4772491abdb7c483387a59ea89889f4be:668f977b054ec9523961a80c18b4173ac44f86b75ed6ab2e157821fa50e407ac) ;;
  *)
    if [ "${AUTOAPI_TEST_ALLOW_VCPKG_SOURCE_URL:-0}" != 1 ] \
      || ! printf '%s' "$baseline" | grep -Eq '^[a-f0-9]{40}$' \
      || ! printf '%s' "$archive_sha256" | grep -Eq '^[a-f0-9]{64}$'; then
      echo "Unsupported vcpkg source archive" >&2
      exit 2
    fi ;;
esac

source_url="https://codeload.github.com/microsoft/vcpkg/tar.gz/$baseline"
git_url="https://github.com/microsoft/vcpkg.git"
if [ -n "${AUTOAPI_TEST_VCPKG_SOURCE_URL:-}" ]; then
  [ "${AUTOAPI_TEST_ALLOW_VCPKG_SOURCE_URL:-0}" = 1 ] || {
    echo "Refusing a non-production vcpkg source URL" >&2
    exit 2
  }
  source_url=$AUTOAPI_TEST_VCPKG_SOURCE_URL
fi
if [ -n "${AUTOAPI_TEST_VCPKG_GIT_URL:-}" ]; then
  [ "${AUTOAPI_TEST_ALLOW_VCPKG_SOURCE_URL:-0}" = 1 ] || {
    echo "Refusing a non-production vcpkg Git URL" >&2
    exit 2
  }
  git_url=$AUTOAPI_TEST_VCPKG_GIT_URL
fi

remaining_seconds() {
  # GNU date (used by the Linux production image) and BSD date (used by
  # macOS) spell ISO-8601 parsing differently. Keep the production path
  # unchanged, then accept only the serialized UTC form emitted for jobs when
  # falling back to BSD date. BSD date cannot parse fractional seconds, so
  # remove them only after validating the complete input.
  if deadline_epoch=$(date -u -d "$deadline_at" +%s 2>/dev/null); then
    :
  elif printf '%s\n' "$deadline_at" \
    | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'; then
    bsd_deadline_at=$(printf '%s\n' "$deadline_at" | sed -E 's/\.[0-9]+Z$/Z/')
    deadline_epoch=$(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$bsd_deadline_at" +%s 2>/dev/null) || {
      echo "Invalid vcpkg job deadline" >&2
      return 2
    }
  else
    echo "Invalid vcpkg job deadline" >&2
    return 2
  fi
  now_epoch=$(date -u +%s)
  remaining=$((deadline_epoch - now_epoch))
  [ "$remaining" -gt 5 ] || {
    echo "Vcpkg source installation cannot start before the job deadline" >&2
    return 2
  }
  printf '%s' "$remaining"
}

commit_marker="$root/.autoapi-vcpkg-commit"
source_marker="$root/.autoapi-vcpkg-source-sha256"
if [ -x "$root/vcpkg" ] \
  && [ "$(cat "$commit_marker" 2>/dev/null || true)" = "$baseline" ] \
  && [ "$(cat "$source_marker" 2>/dev/null || true)" = "$archive_sha256" ] \
  && git -C "$root" cat-file -e "$baseline^{commit}" 2>/dev/null; then
  exit 0
fi

parent=$(dirname "$root")
mkdir -p "$parent"
archive="$parent/vcpkg-$baseline.tar.gz"
if ! printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum -c --status 2>/dev/null; then
  download_budget=$(( $(remaining_seconds) - 5 ))
  [ "$download_budget" -gt 0 ]
  if ! timeout --signal=TERM --kill-after=5s "${download_budget}s" \
    curl --fail --location --retry 3 --retry-all-errors --connect-timeout 15 \
      --continue-at - --output "$archive" "$source_url"; then
    printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum -c --status 2>/dev/null || exit 1
  fi
fi
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum -c -

members="$archive.members"
tar -tzf "$archive" > "$members"
awk -v prefix="vcpkg-$baseline/" '
  BEGIN { count = 0 }
  index($0, prefix) != 1 || $0 ~ /(^|\/)\.\.(\/|$)/ { exit 2 }
  { count += 1 }
  END { if (count == 0) exit 2 }
' "$members"
rm -f "$members"

staging=$(mktemp -d "$parent/.autoapi-vcpkg-source.XXXXXX")
cleanup() {
  rm -rf "$staging"
  rm -f "$members"
}
trap cleanup EXIT INT TERM
tar -xzf "$archive" -C "$staging" --strip-components=1 --no-same-owner --no-same-permissions
[ -f "$staging/bootstrap-vcpkg.sh" ]

# Manifest versioning resolves historical port trees through Git object IDs.
# A codeload archive proves the exact working tree but intentionally contains
# no object database, so retain a pinned partial repository for that resolver.
git -C "$staging" init --quiet
git -C "$staging" config core.autocrlf input
git -C "$staging" remote add origin "$git_url"
fetch_budget=$(( $(remaining_seconds) - 2 ))
[ "$fetch_budget" -gt 0 ]
timeout --signal=TERM --kill-after=2s "${fetch_budget}s" \
  git -C "$staging" fetch --quiet --no-tags --depth=1 --filter=blob:none origin "$baseline"
[ "$(git -C "$staging" rev-parse FETCH_HEAD)" = "$baseline" ]
git -C "$staging" cat-file -e "$baseline^{commit}"

# Bind the fetched commit to the independently SHA-256-verified archive without
# checking out or executing any network-supplied working-tree content.
expected_tree=$(git -C "$staging" rev-parse "$baseline^{tree}")
tree_index="$parent/.autoapi-vcpkg-tree-index.$$"
# The exact commit may intentionally track paths matched by its own ignore
# rules. A fresh index has no tracked-path memory, so force-add every archive
# member before comparing trees.
GIT_INDEX_FILE="$tree_index" git -C "$staging" add -f -A
actual_tree=$(GIT_INDEX_FILE="$tree_index" git -C "$staging" write-tree)
[ "$actual_tree" = "$expected_tree" ] || {
  echo "Verified vcpkg archive does not match the pinned Git commit ($actual_tree != $expected_tree)" >&2
  rm -f "$tree_index"
  exit 1
}
rm -f "$tree_index"

bootstrap_budget=$(( $(remaining_seconds) - 2 ))
[ "$bootstrap_budget" -gt 0 ]
timeout --signal=TERM --kill-after=2s "${bootstrap_budget}s" \
  sh "$staging/bootstrap-vcpkg.sh" -disableMetrics
[ -x "$staging/vcpkg" ]
printf '%s\n' "$baseline" > "$staging/.autoapi-vcpkg-commit"
printf '%s\n' "$archive_sha256" > "$staging/.autoapi-vcpkg-source-sha256"

rm -rf "$root"
mv "$staging" "$root"
trap - EXIT INT TERM
