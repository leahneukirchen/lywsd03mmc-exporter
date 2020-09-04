# lywsd03mmc-exporter — a Prometheus exporter for the LYWSD03MMC BLE thermometer

lywsd03mmc-exporter is a small tool to scan and keep track of
Bluetooth beacons the LYWSD03MMC BLE thermometer sends periodically.
It can then be scraped by Prometheus, by default on `:9265/metrics`.

## Exposed metrics

```
thermometer_temperature_celsius{mac="...",sensor="LYWSD03MMC"} 25.9
thermometer_humidity_ratio{mac="...",sensor="LYWSD03MMC"} 53
thermometer_battery_ratio{mac="...",sensor="LYWSD03MMC"} 91
thermometer_rssi_dbm{mac="...",sensor="LYWSD03MMC"} -35
```

Additionally, the ATC_MiThermometer custom firmware exposes:

```
thermometer_battery_volts{mac="...",sensor="LYWSD03MMC"} 3.005
thermometer_frame_current{mac="...",sensor="LYWSD03MMC"} 165
```

## Modes of operation

Due to talking to lower levels of the Bluetooth stack,
lywsd03mmc-exporter needs to be run as `root` or with CAP_NET_ADMIN.

### Stock firmware

To use lywsd03mmc-exporter with the
[stock firmware](https://github.com/custom-components/sensor.mitemp_bt/files/4022697/d4135e135443ba86e403ecb2af2bf0af_upd_miaomiaoce.sensor_ht.t2.zip),
you need to *activate* your device and extract the *Mi Bindkey*.  You
can either use the Xiaomi Home software for that (requires an account
and a HTTPS MITM attack on your phone), or more easily, use the
[TelinkFlasher](https://atc1441.github.io/TelinkFlasher.html) provided
by [@atc1441](https://github.com/atc1441).

You will need to create a keyfile in a format like this,
and use `-k file`:

```
# format: MAC KEY, hex digits only
A4C138FFFFFF 00112233445566778899aabbccddeeff
```

This mode sends measurements every 10 minutes.

Note: Supposedly, the battery ratio is always 100% unless the battery
is really empty.

### Custom firmware

@atc1441 wrote a [custom firmware](https://github.com/atc1441/ATC_MiThermometer)
for the LYWSD03MMC.  It sends data unencrypted in beacons.
You can flash it easily with above TelinkFlasher.

This mode sends measurements every 10 seconds.

### Polling mode

This is yet to be implemented.
It requires an active connection to the device.

## Copying

lywsd03mmc-exporter is licensed under the MIT license.

## Thanks

This software would not be possible without the help of code and
documentation in:

* https://github.com/atc1441/ATC_MiThermometer
* https://github.com/danielkucera/mi-standardauth
* https://github.com/ahpohl/xiaomi_lywsd03mmc
* https://github.com/custom-components/sensor.mitemp_bt
* https://github.com/JsBergbau/MiTemperature2
* https://github.com/lcsfelix/reading-xiaomi-temp
* https://tasmota.github.io/docs/Bluetooth/
* https://github.com/DazWilkin/gomijia2
