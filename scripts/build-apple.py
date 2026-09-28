#!/usr/bin/env python3
"""Build the CLI containing app and packet-tunnel system extension. Never install/start."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY = "packet-tunnel-provider-systemextension"


def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def profile(path, bundle_id, team, host=False):
    data = subprocess.check_output(["security", "cms", "-D", "-i", str(path)])
    value = plistlib.loads(data)
    ent = value["Entitlements"]
    app_id = ent.get("com.apple.application-identifier", ent.get("application-identifier"))
    if app_id != f"{team}.{bundle_id}":
        raise ValueError(f"Profile does not match {team}.{bundle_id}")
    if team not in value.get("TeamIdentifier", []):
        raise ValueError("Profile team mismatch")
    if value["ExpirationDate"] <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        raise ValueError("Provisioning profile expired")
    if CAPABILITY not in ent.get("com.apple.developer.networking.networkextension", []):
        raise ValueError(f"Profile must grant {CAPABILITY}")
    if host and not ent.get("com.apple.developer.system-extension.install"):
        raise ValueError("App profile must grant com.apple.developer.system-extension.install")
    requested = {
        "com.apple.application-identifier": app_id,
        "com.apple.developer.team-identifier": team,
        "com.apple.developer.networking.networkextension": [CAPABILITY],
    }
    if host:
        requested["com.apple.developer.system-extension.install"] = True
    return requested


def plist(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        plistlib.dump(value, f)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-id", default="dev.jamilbk.interestun")
    parser.add_argument("--team-id")
    parser.add_argument("--identity", help="codesign identity; requires both provisioning profiles")
    parser.add_argument("--automatic-signing", action="store_true", help="Use Xcode's signed-in account to provision development IDs/profiles for --team-id")
    parser.add_argument("--app-profile", type=Path)
    parser.add_argument("--extension-profile", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "target/apple")
    parser.add_argument("--packet-flow", action="store_true", help="Build the public packet-flow frontend instead of using the existing NE utun descriptor")
    args = parser.parse_args()
    provisioned = bool(args.identity or args.automatic_signing)
    if args.automatic_signing:
        if not args.team_id or any([args.identity, args.app_profile, args.extension_profile]):
            parser.error("--automatic-signing requires --team-id and cannot be combined with manual profiles/identity")
    elif any([args.identity, args.app_profile, args.extension_profile, args.team_id]) and not all(
        [args.identity, args.app_profile, args.extension_profile, args.team_id]
    ):
        parser.error("Signing requires --identity, --team-id, --app-profile and --extension-profile together")
    if not all(c.isalnum() or c in ".-" for c in args.bundle_id) or "." not in args.bundle_id:
        parser.error("Invalid bundle ID")
    extension_id = args.bundle_id + ".packet-tunnel"
    # macOS team-prefixed app groups also scope the provider's Mach service.
    # This is required by NE category validation even without shared storage.
    app_group = f"{args.team_id or 'UNSIGNED'}.{args.bundle_id}"
    app_ent = profile(args.app_profile, args.bundle_id, args.team_id, host=True) if args.identity else {}
    ext_ent = profile(args.extension_profile, extension_id, args.team_id) if args.identity else {}
    if args.automatic_signing:
        # Development profiles use the unsuffixed capability, including when
        # packaging a system extension. Developer ID profiles use the suffix.
        ext_ent = {"com.apple.developer.networking.networkextension": ["packet-tunnel-provider"]}
        app_ent = {**ext_ent, "com.apple.developer.system-extension.install": True}
    if provisioned:
        for ent in (app_ent, ext_ent):
            ent["com.apple.security.application-groups"] = [app_group]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".build-", dir=output))
    version = str(int(time.time()))
    app = stage / "Interestun.app"
    extension = app / "Contents/Library/SystemExtensions" / (extension_id + ".systemextension")
    for bundle in (app, extension):
        (bundle / "Contents/MacOS").mkdir(parents=True)
    common = {
        "CFBundleInfoDictionaryVersion": "6.0", "CFBundleVersion": version,
        "CFBundleShortVersionString": "0.1.0", "CFBundleDevelopmentRegion": "en",
        "LSMinimumSystemVersion": "15.0",
    }
    plist(app / "Contents/Info.plist", {
        **common, "CFBundleIdentifier": args.bundle_id, "CFBundleExecutable": "interestunctl",
        "CFBundleName": "Interestun", "CFBundlePackageType": "APPL", "LSUIElement": True,
        "InterestunExtensionIdentifier": extension_id, "InterestunSignedForActivation": provisioned,
        "NSSystemExtensionUsageDescription": "Interestun uses a packet tunnel system extension to test encrypted networking.",
    })
    plist(extension / "Contents/Info.plist", {
        **common, "CFBundleIdentifier": extension_id, "CFBundleExecutable": "InterestunPacketTunnel",
        "CFBundleName": "InterestunPacketTunnel", "CFBundlePackageType": "SYSX",
        "NSSystemExtensionUsageDescription": "Provides the Interestun packet tunnel.",
        "NetworkExtension": {
            "NEMachServiceName": app_group + ".packet-tunnel",
            "NEProviderClasses": {"com.apple.networkextension.packet-tunnel": "InterestunPacketTunnel.PacketTunnelProvider"},
        },
    })
    run("cargo", "build", "--locked", "--release", "--lib", "--features", "apple-packet-tunnel", cwd=ROOT,
        env={**os.environ, "MACOSX_DEPLOYMENT_TARGET": "15.0"})
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version=1"], cwd=ROOT))
    library = Path(metadata["target_directory"]) / "release/libinterestun.a"
    sdk = subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip()
    arch = {"arm64": "arm64", "x86_64": "x86_64"}[platform.machine()]
    flags = ["-O", "-g", "-swift-version", "5", "-warnings-as-errors", "-sdk", sdk,
             "-target", f"{arch}-apple-macosx15.0", "-import-objc-header", ROOT / "apple/Bridge/Interestun.h",
             "-framework", "Foundation", "-framework", "NetworkExtension", "-framework", "Network",
             "-Xlinker", "-dead_strip", library]
    shared = ROOT / "apple/Shared/Configuration.swift"
    if args.packet_flow:
        flags += ["-D", "INTERESTUN_PACKET_FLOW"]
    if args.automatic_signing:
        from apple_xcode import generate
        plist(stage / (app.name + ".entitlements"), app_ent)
        plist(stage / (extension.name + ".entitlements"), ext_ent)
        project = generate(stage, ROOT, app, extension, library, args.team_id, packet_flow=args.packet_flow)
        log = stage / "xcodebuild.log"
        products = stage / "products"
        with log.open("wb") as f:
            built = subprocess.run(["xcodebuild", "-quiet", "-project", str(project), "-target", "Interestun",
                "-configuration", "Release", "-allowProvisioningUpdates", f"CONFIGURATION_BUILD_DIR={products}",
                f"OBJROOT={stage / 'objects'}", f"ARCHS={arch}", "build"], stdout=f, stderr=subprocess.STDOUT)
        if built.returncode:
            raise RuntimeError(f"Xcode build/provisioning failed; inspect {log}")
        app = products / "Interestun.app"
        extension = app / "Contents/Library/SystemExtensions" / (extension_id + ".systemextension")
        run("codesign", "--verify", "--strict", extension)
        run("codesign", "--verify", "--strict", app)
    else:
        run("xcrun", "swiftc", *flags, "-framework", "SystemExtensions", "-module-name", "InterestunCLI",
            shared, ROOT / "apple/CLI/main.swift", "-o", app / "Contents/MacOS/interestunctl")
        run("xcrun", "swiftc", *flags, "-module-name", "InterestunPacketTunnel", shared,
            ROOT / "apple/Extension/PacketTunnelProvider.swift", ROOT / "apple/Extension/main.swift",
            "-o", extension / "Contents/MacOS/InterestunPacketTunnel")
    for bundle, ent, provisioning in [(extension, ext_ent, args.extension_profile), (app, app_ent, args.app_profile)]:
        if args.automatic_signing:
            continue
        ent_file = stage / (bundle.name + ".entitlements")
        plist(ent_file, ent)
        if provisioned:
            shutil.copyfile(provisioning, bundle / "Contents/embedded.provisionprofile")
            run("codesign", "--force", "--sign", args.identity, "--options", "runtime", "--timestamp",
                "--entitlements", ent_file, bundle)
        else:
            # Restricted entitlements without profiles can prevent even --help
            # from launching. Ad-hoc builds intentionally contain no such grants.
            run("codesign", "--force", "--sign", "-", bundle)
        run("codesign", "--verify", "--strict", bundle)
    manifest = {
        "version": version, "architecture": arch, "app_id": args.bundle_id, "extension_id": extension_id,
        "provisioned": provisioned, "installed": False, "tunnel_started": False,
        "signing": "automatic development" if args.automatic_signing else "manual" if args.identity else "ad-hoc",
        "team_id": args.team_id,
        "app_group": app_group,
        "rust_features": ["default", "apple-packet-tunnel"], "skywalk": "unverified",
        "tun_frontend": "NEPacketTunnelFlow" if args.packet_flow else "Network Extension utun descriptor",
        "sha256": {str(p.relative_to(app)): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                   [app / "Contents/MacOS/interestunctl", extension / "Contents/MacOS/InterestunPacketTunnel"]},
    }
    destination = output / "Interestun.app"
    if destination.exists():
        # Preserve previous build rather than silently deleting an app bundle.
        os.rename(destination, output / ("Interestun.previous." + stage.name + ".app"))
    os.rename(app, destination)
    manifest["bundle"] = str(destination)
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(destination)
    print("Provisioned build; not installed or started." if provisioned else
          "Unprovisioned build: --help and validate work; activation is disabled.")


if __name__ == "__main__":
    main()
