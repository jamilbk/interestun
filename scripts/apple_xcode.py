"""Generate a small native Xcode project for automatic development provisioning."""
from pathlib import Path
import plistlib


def generate(stage: Path, root: Path, app: Path, extension: Path, library: Path, team: str, *, packet_flow=False, ethernet=False):
    objects = {}

    def add(isa, **values):
        key = f"{len(objects) + 1:024X}"
        objects[key] = {"isa": isa, **values}
        return key

    def configs(settings):
        config = add("XCBuildConfiguration", name="Release", buildSettings=settings)
        return add("XCConfigurationList", buildConfigurations=[config], defaultConfigurationIsVisible=0,
                   defaultConfigurationName="Release")

    def source(path):
        ref = add("PBXFileReference", lastKnownFileType="sourcecode.swift", path=str(path), sourceTree="<absolute>")
        return ref, add("PBXBuildFile", fileRef=ref)

    shared = source(root / "apple/Shared/Configuration.swift")
    cli = source(root / "apple/CLI/main.swift")
    provider = source(root / "apple/Extension/PacketTunnelProvider.swift")
    entry = source(root / "apple/Extension/main.swift")
    app_product = add("PBXFileReference", explicitFileType="wrapper.application", path="Interestun.app", sourceTree="BUILT_PRODUCTS_DIR")
    ext_product = add("PBXFileReference", explicitFileType="wrapper.system-extension", path=extension.name, sourceTree="BUILT_PRODUCTS_DIR")
    products = add("PBXGroup", name="Products", children=[app_product, ext_product], sourceTree="<group>")
    group = add("PBXGroup", children=[shared[0], cli[0], provider[0], entry[0], products], sourceTree="<group>")

    common = {
        "SDKROOT": "macosx", "MACOSX_DEPLOYMENT_TARGET": "15.0", "SWIFT_VERSION": "5.0",
        "SWIFT_OPTIMIZATION_LEVEL": "-O", "SWIFT_TREAT_WARNINGS_AS_ERRORS": "YES",
        "SWIFT_OBJC_BRIDGING_HEADER": str(root / "apple/Bridge/Interestun.h"),
        "SWIFT_INSTALL_OBJC_HEADER": "NO", "CLANG_ENABLE_MODULES": "YES",
        "GENERATE_INFOPLIST_FILE": "NO", "CODE_SIGN_STYLE": "Automatic", "DEVELOPMENT_TEAM": team,
        "CODE_SIGN_IDENTITY": "Apple Development", "ENABLE_HARDENED_RUNTIME": "YES",
        "OTHER_LDFLAGS": [str(library), "-framework", "Foundation", "-framework", "Network",
                          "-framework", "NetworkExtension", "-framework", "SystemExtensions"],
        "LD_RUNPATH_SEARCH_PATHS": ["$(inherited)", "@executable_path/../Frameworks"],
        "ONLY_ACTIVE_ARCH": "YES", "SKIP_INSTALL": "NO", "DEBUG_INFORMATION_FORMAT": "dwarf-with-dsym",
        "SWIFT_ACTIVE_COMPILATION_CONDITIONS": "INTERESTUN_ETHERNET" if ethernet else "INTERESTUN_PACKET_FLOW" if packet_flow else "",
    }

    def target(name, bundle, product, module, executable, files, product_type):
        info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
        settings = {**common, "PRODUCT_BUNDLE_IDENTIFIER": info["CFBundleIdentifier"],
                    "PRODUCT_NAME": name, "PRODUCT_MODULE_NAME": module, "EXECUTABLE_NAME": executable,
                    "INFOPLIST_FILE": str(bundle / "Contents/Info.plist"),
                    "CODE_SIGN_ENTITLEMENTS": str(stage / (bundle.name + ".entitlements"))}
        phase = add("PBXSourcesBuildPhase", buildActionMask=2147483647, files=files, runOnlyForDeploymentPostprocessing=0)
        return add("PBXNativeTarget", name=name, productName=name, productReference=product, productType=product_type,
                   buildConfigurationList=configs(settings), buildPhases=[phase], buildRules=[], dependencies=[])

    ext = target(extension.stem, extension, ext_product, "InterestunPacketTunnel", "InterestunPacketTunnel",
                 [shared[1], provider[1], entry[1]], "com.apple.product-type.system-extension")
    host = target("Interestun", app, app_product, "InterestunCLI", "interestunctl",
                  [shared[1], cli[1]], "com.apple.product-type.application")
    copy = add("PBXBuildFile", fileRef=ext_product, settings={"ATTRIBUTES": ["RemoveHeadersOnCopy"]})
    embed = add("PBXCopyFilesBuildPhase", buildActionMask=2147483647, dstPath="$(SYSTEM_EXTENSIONS_FOLDER_PATH)",
                dstSubfolderSpec=16, files=[copy], name="Embed System Extensions", runOnlyForDeploymentPostprocessing=0)
    objects[host]["buildPhases"].append(embed)
    project = add("PBXProject", buildConfigurationList=configs({}), compatibilityVersion="Xcode 14.0",
                  mainGroup=group, productRefGroup=products, projectDirPath="", projectRoot="", targets=[host, ext],
                  developmentRegion="en", knownRegions=["en", "Base"],
                  attributes={"LastUpgradeCheck": "1600", "TargetAttributes": {
                      key: {"DevelopmentTeam": team, "ProvisioningStyle": "Automatic"} for key in (host, ext)}})
    proxy = add("PBXContainerItemProxy", containerPortal=project, proxyType=1, remoteGlobalIDString=ext,
                remoteInfo=extension.stem)
    objects[host]["dependencies"] = [add("PBXTargetDependency", target=ext, targetProxy=proxy)]
    path = stage / "Interestun.xcodeproj"
    path.mkdir()
    with (path / "project.pbxproj").open("wb") as f:
        plistlib.dump({"archiveVersion": "1", "classes": {}, "objectVersion": "56", "objects": objects,
                      "rootObject": project}, f, sort_keys=False)
    return path
