from storage import cache, common, device
from trezor import config


def set_current_version() -> None:
    device.set_version(common.STORAGE_VERSION_CURRENT)


def wipe() -> None:
    config.wipe()
    cache.clear_all()


def init_unlocked() -> None:
    # Check for storage version upgrade.
    version = device.get_version()
    if version == common.STORAGE_VERSION_01:
        _migrate_from_version_01()
    if not device.is_initialized() and device.get_version():
        common.set_bool(common.APP_DEVICE, device.INITIALIZED, True, public=True)


def reset_storage() -> None:
    device_id = device.get_device_id()
    wipe()
    device.set_device_id(device_id)
    set_current_version()


def _migrate_from_version_01() -> None:
    # Make the U2F counter public and writable even when storage is locked.
    # U2F counter wasn't public, so we are intentionally not using storage.device module.
    counter = common.get(common.APP_DEVICE, device.U2F_COUNTER)
    if counter is not None:
        device.set_u2f_counter(int.from_bytes(counter, "big"))
        # Delete the old, non-public U2F_COUNTER.
        common.delete(common.APP_DEVICE, device.U2F_COUNTER)
    set_current_version()
