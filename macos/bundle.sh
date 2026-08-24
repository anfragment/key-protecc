#!/bin/sh
# Wrap a Mach-O binary in a signed .app bundle.
#
# Persisting a Secure Enclave key needs the keychain-access-groups entitlement. macOS only
# honours that entitlement when a provisioning profile allowlists it, and profiles are read
# from Contents/embedded.provisionprofile and nowhere else. A signed bare binary carrying the
# entitlement is killed by AMFI at exec (SIGKILL, exit 137), so there is no way to exercise the
# Enclave path straight out of `go build` or `go test` - it has to be bundled first. That is
# what this script exists for.
#
# Usage: macos/bundle.sh <binary> <output.app>
#
# Settings come from the environment, or from macos/signing.env if that file exists. See
# macos/signing.env.example; the real one is not committed, because a team ID and an app ID
# belong to whoever is building rather than to the project.
#
#   KP_TEAM_ID        Apple Developer team ID. Required. Read it from the OU field of your
#                     signing certificate, not from the parenthetical in its common name -
#                     that one is the certificate's own ID.
#   KP_BUNDLE_ID      Bundle identifier. Required. Must be the app ID the profile was issued
#                     for; anything else and AMFI rejects the profile.
#   KP_PROFILE        Provisioning profile to embed.
#   KP_SIGN_IDENTITY  codesign identity. An "Apple Development" certificate pairs with a
#                     macOS App Development profile, which is locked to registered devices;
#                     "Developer ID Application" pairs with a Developer ID profile, which sets
#                     ProvisionsAllDevices and is what a shipping build uses.
set -eu

binary=${1:?usage: macos/bundle.sh <binary> <output.app>}
app=${2:?usage: macos/bundle.sh <binary> <output.app>}

here=$(dirname "$0")
exe=$(basename "$binary")

if [ -f "$here/signing.env" ]; then
	. "$here/signing.env"
fi

: "${KP_TEAM_ID:?set KP_TEAM_ID, or copy macos/signing.env.example to macos/signing.env}"
: "${KP_BUNDLE_ID:?set KP_BUNDLE_ID, or copy macos/signing.env.example to macos/signing.env}"
: "${KP_PROFILE:=macos/embedded.provisionprofile}"
: "${KP_SIGN_IDENTITY:=Apple Development}"

if [ ! -f "$binary" ]; then
	echo "bundle.sh: no such binary: $binary" >&2
	exit 1
fi
if [ ! -f "$KP_PROFILE" ]; then
	echo "bundle.sh: no provisioning profile at $KP_PROFILE" >&2
	echo "bundle.sh: download one from developer.apple.com for app ID $KP_BUNDLE_ID," >&2
	echo "bundle.sh: or point KP_PROFILE at it" >&2
	exit 1
fi

subst() {
	sed -e "s/@EXECUTABLE@/$exe/g" \
		-e "s/@BUNDLE_ID@/$KP_BUNDLE_ID/g" \
		-e "s/@TEAM_ID@/$KP_TEAM_ID/g" "$1"
}

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp "$binary" "$app/Contents/MacOS/$exe"
cp "$KP_PROFILE" "$app/Contents/embedded.provisionprofile"
subst "$here/Info.plist.tmpl" >"$app/Contents/Info.plist"

# The entitlements only exist to be read by codesign, so they are never written into the tree.
entitlements=$(mktemp -t kp-entitlements)
trap 'rm -f "$entitlements"' EXIT
subst "$here/entitlements.plist.tmpl" >"$entitlements"

# --options runtime enables the hardened runtime, which drops get-task-allow. Without that the
# process is debuggable and another process could read an in-memory signing key out of it.
codesign --force --options runtime \
	--entitlements "$entitlements" \
	--sign "$KP_SIGN_IDENTITY" \
	"$app"

echo "bundle.sh: signed $app as $KP_SIGN_IDENTITY"
