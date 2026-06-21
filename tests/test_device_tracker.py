from custom_components.zeekr_ev.device_tracker import ZeekrDeviceTracker


class DummyCoordinator:
    def __init__(self, data):
        self.data = data


def test_latitude_longitude_parsing():
    data = {
        "VIN1": {
            "basicVehicleStatus": {"position": {"latitude": "12.34", "longitude": "56.78"}}
        }
    }
    coordinator = DummyCoordinator(data)
    dt = ZeekrDeviceTracker(coordinator, "VIN1")
    assert dt.latitude == 12.34
    assert dt.longitude == 56.78


def test_latitude_longitude_invalid_values():
    data = {"VIN1": {"basicVehicleStatus": {"position": {"latitude": "notafloat", "longitude": None}}}}
    coordinator = DummyCoordinator(data)
    dt = ZeekrDeviceTracker(coordinator, "VIN1")
    assert dt.latitude is None
    assert dt.longitude is None
