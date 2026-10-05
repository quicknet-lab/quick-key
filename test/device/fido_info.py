from fido2.hid import CtapHidDevice, CTAPHID
from fido2.ctap2 import Ctap2
from fido2.ctap1 import Ctap1
devs = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209]
print("devices:", [(hex(d.descriptor.vid), hex(d.descriptor.pid), d.descriptor.product_name) for d in devs])
dev = devs[0]
print("ctaphid version/caps:", dev.version, dev.device_version, hex(dev.capabilities))
print("ping:", dev.call(CTAPHID.PING, b"hello" * 30) == b"hello" * 30)
ctap = Ctap2(dev)
info = ctap.get_info()
print(info)
from fido2.ctap2.pin import ClientPin
print("pin retries:", ClientPin(ctap).get_pin_retries())
print("u2f version:", Ctap1(dev).get_version())
dev.wink()
print("vendor version:", dev.call(0xC1).hex())
