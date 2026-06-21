# Zeekr EV Integration for Home Assistant

Custom integration for Zeekr Electric Vehicles, with **China mainland +86 SMS code login** support.

## Two Login Methods

### Method 1: SMS Code (+86 China mainland) — NEW
- Based on [flows.json](flows.json) reverse engineering
- Uses phone number + SMS verification code
- No additional keys required
- Three-API-gateway auth pipeline (JWT → AccessToken → SNCTSP)
- Powered by `api_sms.py` using built-in signers

### Method 2: Email + Password (original)
- Uses [zeekr_ev_api](https://github.com/Fryyyyy/zeekr_ev_api) library
- Requires HMAC keys, VIN encryption keys from app decompilation
- Recommended to create a separate shared account

## Features

- **Climate**: Control Heating / Cooling Vents & Seats and Steering Wheel
- **Sensors**: Battery Level, Range, Odometer, Interior Temperature, Tire Pressures, Charging Power, Voltage, Speed
- **Binary Sensors**: Charging Status, Plugged In Status, Doors, Tyre Warnings
- **Buttons**: Flash blinkers, enable/disable Sentry Mode
- **Locks**: Door and Trunk Lock
- **Device Tracker**: Location tracking
- **Covers**: Charging port, Windows, Sunroof, Trunk
- **Numbers**: Charging limit, AC temperature
- **Selects**: Drive mode, Steering mode, Energy recovery mode
- **Switches**: Sentry mode, Valet mode, Brake hold, Speed limit
- **Datetime / Time**: Scheduled charging
- **Services**: get_trip_trackpoints

## Installation

### HACS
1. Open HACS
2. Add this repository as a custom repository (Integration)
3. Search for "Zeekr EV Integration" and install
4. Restart Home Assistant

### Manual
1. Copy the `custom_components/zeekr_ev` folder to your Home Assistant `config/custom_components/` directory
2. Restart Home Assistant

## Configuration

### SMS Login (Recommended for China)
1. Go to Settings -> Devices & Services -> Add Integration
2. Search for "Zeekr EV"
3. Select "SMS Login"
4. Choose region code (+86 for China mainland)
5. Enter phone number
6. Enter SMS verification code
7. Complete

### Email Login
1. Go to Settings -> Devices & Services -> Add Integration
2. Search for "Zeekr EV"
3. Select "Email Login"
4. Enter email, password, country code, and API keys
5. Complete

## Tips

- **Account**: Create a new account and share your car with it to avoid "The account is currently logged in elsewhere"
- **Display**: Use vehicle-status-card for a good quality dashboard
- **Secrets for email login**: Get the secrets by decompiling the Android app

## API Architecture (SMS Login)

Based on Node-RED flows.json analysis, the SMS login uses three gateways:

| Gateway | URL | Signing | Purpose |
|---------|-----|---------|---------|
| JWT Gateway | api-gw-toc.zeekrlife.com | SHA1 sorted-sign | SMS, login, auth code |
| Line Gateway | api.zeekrline.com | HMAC-SHA1 | Ecar login, vehicle status |
| SNCTSP Gateway | snc-tsp-api.zeekrlife.com | HMAC-SHA256 + AES VIN | Vehicle list, latest status |

## Issues

Please report issues on the [GitHub Issue Tracker](https://github.com/Fryyyyy/zeekr_homeassistant/issues).

## License

MIT
