#!/usr/bin/env vpython3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

# Copyright 2018 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import os
import platform
import plistlib
import subprocess
import sys
import pkg_resources

from urllib.error import URLError  # pylint: disable=no-name-in-module,import-error

import deps
from deps_config import DEPS_PACKAGES_URL


def LoadPList(path):
    """Loads Plist at |path| and returns it as a dictionary."""
    with open(path, 'rb') as f:
        return plistlib.load(f)


# This contains binaries from Xcode 13.2.1 13C100, along with the macOS 12 SDK
XCODE_VERSION = '13.2.1'
HERMETIC_XCODE_BINARY = (
    DEPS_PACKAGES_URL +
    '/xcode-hermetic-toolchain/xcode-hermetic-toolchain-xcode-' +
    XCODE_VERSION + '-sdk-12.1-12.0.tar.gz')

# The toolchain will not be downloaded if the minimum OS version is not met. 19
# is the major version number for macOS 10.15. Xcode 13.2 13C90 only runs on
# 11.3 and newer, but some bots are still running older OS versions. 10.15.4,
# the OS minimum through Xcode 12.4, still seems to work.
MAC_MINIMUM_OS_VERSION = [19, 4]

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', '..', 'build'))
TOOLCHAIN_ROOT = os.path.join(BASE_DIR, 'mac_files')
TOOLCHAIN_BUILD_DIR = os.path.join(TOOLCHAIN_ROOT, 'Xcode.app')


def PlatformMeetsHermeticXcodeRequirements():
    if sys.platform != 'darwin':
        return False
    needed = MAC_MINIMUM_OS_VERSION
    major_version = [
        int(v) for v in platform.release().split('.')[:len(needed)]
    ]
    return major_version >= needed


def GetHermeticXcodeVersion(binaries_root):
    hermetic_xcode_version_plist_path = os.path.join(binaries_root,
                                                     'Contents/version.plist')

    if not os.path.exists(hermetic_xcode_version_plist_path):
        return ''

    hermetic_xcode_version_plist = LoadPList(hermetic_xcode_version_plist_path)
    return hermetic_xcode_version_plist['CFBundleShortVersionString']


def InstallXcodeBinaries():
    """Installs the Xcode binaries and accepts the license."""

    # only download for Brave goma users
    if os.environ.get('npm_config_goma_server_host') != 'goma.brave.com':
        print("Goma server host is not configured for Brave")
        return 0

    binaries_root = os.path.join(TOOLCHAIN_ROOT, 'xcode_binaries')
    if (XCODE_VERSION == GetHermeticXcodeVersion(binaries_root) and
            not os.path.islink(binaries_root)):
        print(f"Hermetic Xcode {XCODE_VERSION} already installed")
        return 0

    url = HERMETIC_XCODE_BINARY
    print(f"Downloading hermetic Xcode: {url}")
    try:
        deps.DownloadAndUnpack(url, binaries_root)
    except URLError:
        print(f"Failed to download hermetic Xcode: {url}")
        print("Exiting.")
        return 1

    # Accept the license for this version of Xcode if it's newer than the
    # currently accepted version.
    hermetic_xcode_version = GetHermeticXcodeVersion(binaries_root)

    hermetic_xcode_license_path = os.path.join(
        binaries_root, 'Contents/Resources/LicenseInfo.plist')
    hermetic_xcode_license_plist = LoadPList(hermetic_xcode_license_path)
    hermetic_xcode_license_version = hermetic_xcode_license_plist['licenseID']

    should_overwrite_license = True
    current_license_path = '/Library/Preferences/com.apple.dt.Xcode.plist'
    if os.path.exists(current_license_path):
        current_license_plist = LoadPList(current_license_path)
        xcode_version = current_license_plist.get(
            'IDEXcodeVersionForAgreedToGMLicense')
        if (xcode_version is not None and
                pkg_resources.parse_version(xcode_version) >=
                pkg_resources.parse_version(hermetic_xcode_version)):
            should_overwrite_license = False

    if not should_overwrite_license:
        return 0

    # Use puppet's sudoers script to accept the license if its available.
    license_accept_script = '/usr/local/bin/xcode_accept_license.py'
    if os.path.exists(license_accept_script):
        args = [
            'sudo', license_accept_script, '--xcode-version',
            hermetic_xcode_version, '--license-version',
            hermetic_xcode_license_version
        ]
        subprocess.check_call(args)
        return 0

    # Otherwise manually accept the license. This will prompt for sudo.
    print('Accepting new Xcode license. Requires sudo.')
    sys.stdout.flush()
    args = [
        'sudo', 'defaults', 'write', current_license_path,
        'IDEXcodeVersionForAgreedToGMLicense', hermetic_xcode_version
    ]
    subprocess.check_call(args)
    args = [
        'sudo', 'defaults', 'write', current_license_path,
        'IDELastGMLicenseAgreedTo', hermetic_xcode_license_version
    ]
    subprocess.check_call(args)
    args = ['sudo', 'plutil', '-convert', 'xml1', current_license_path]
    subprocess.check_call(args)

    return 0


def main():
    parser = argparse.ArgumentParser(description='Download hermetic Xcode.')
    parser.parse_args()

    if not PlatformMeetsHermeticXcodeRequirements():
        print('OS version does not support hermetic Xcode toolchain.')
        return 0

    return InstallXcodeBinaries()


if __name__ == '__main__':
    sys.exit(main())
