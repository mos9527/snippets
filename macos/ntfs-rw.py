# Prerequisites:
# - https://macfuse.github.io/
# - brew install gromgit/fuse/ntfs-3g-mac
# Run this script to re-mount all NTFS volumes in read-write mode.
import subprocess
import plistlib


def cmd(*command):
    try:
        return 0, subprocess.check_output(command)
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output


if __name__ == "__main__":
    ret, plist = cmd("diskutil", "list", "-plist")
    disks = plistlib.loads(plist)
    disks = disks["AllDisksAndPartitions"]
    ntfs = [
        vol
        for disk in disks
        for vol in disk["Partitions"]
        if "Microsoft Basic Data" in vol["Content"]
        # NTFS gets mounted as "Microsoft Basic Data"
        # ..while exFAT gets mounted as "Windows_NTFS". Weird.
    ]
    for part in ntfs:
        dev = part["DeviceIdentifier"]
        ret, result = cmd("diskutil", "unmount", dev)
    for part in ntfs:
        dev, vol = part["DeviceIdentifier"], part["VolumeName"]
        ret, result = cmd(
            "sudo",
            "ntfs-3g",
            f"/dev/{dev}",
            "/Volumes/" + vol,
            "-o",
            "auto_xattr",
            "-o",
            f"volname={vol}",
        )
        if ret:
            print(f'Failed to mount "{vol}"')
        else:
            print(f'NTFS Volume "{vol}" (/dev/{dev}) available at "/Volumes/{vol}"')
