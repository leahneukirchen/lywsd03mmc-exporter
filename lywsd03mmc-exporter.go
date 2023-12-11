// lywsd03mmc-exporter - a Prometheus exporter for the LYWSD03MMC BLE thermometer

// Copyright (C) 2020 Leah Neukirchen <leah@vuxu.org>
// Licensed under the terms of the MIT license, see LICENSE.

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ble/ble"
	"github.com/go-ble/ble/examples/lib/dev"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"crypto/aes"

	aesccm "github.com/pschlump/AesCCM"
)

var (
	tempGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "temperature_celsius",
			Help:      "Temperature in Celsius.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
	humGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "humidity_ratio",
			Help:      "Humidity in percent.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
	battGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "battery_ratio",
			Help:      "Battery in percent.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
	voltGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "battery_volts",
			Help:      "Battery in Volt.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
	frameGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "frame_current",
			Help:      "Current frame number.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
	rssiGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "rssi_dbm",
			Help:      "Received Signal Strength Indication.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
)

const Sensor = "LYWSD03MMC"
const TelinkVendorPrefix = "a4:c1:38"

var EnvironmentalSensingUUID = ble.UUID16(0x181a)
var XiaomiIncUUID = ble.UUID16(0xfe95)

const ExpiryAtc = 2.5 * 10 * time.Second
const ExpiryStock = 2.5 * 10 * time.Minute
const ExpiryConn = 2.5 * 10 * time.Second

var expirers = make(map[string]*time.Timer)
var expirersLock sync.Mutex

func bump(mac string, expiry time.Duration) {
	expirersLock.Lock()
	if t, ok := expirers[mac]; ok {
		t.Reset(expiry)
	} else {
		expirers[mac] = time.AfterFunc(expiry, func() {
			fmt.Printf("expiring %s\n", mac)
			tempGauge.DeleteLabelValues(Sensor, mac)
			humGauge.DeleteLabelValues(Sensor, mac)
			battGauge.DeleteLabelValues(Sensor, mac)
			voltGauge.DeleteLabelValues(Sensor, mac)
			frameGauge.DeleteLabelValues(Sensor, mac)
			rssiGauge.DeleteLabelValues(Sensor, mac)

			expirersLock.Lock()
			delete(expirers, mac)
			expirersLock.Unlock()
		})
	}
	expirersLock.Unlock()
}

func macWithColons(mac string) string {
	return strings.ToUpper(fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		mac[0:2],
		mac[2:4],
		mac[4:6],
		mac[6:8],
		mac[8:10],
		mac[10:12]))
}

func macWithoutColons(mac string) string {
	return strings.ReplaceAll(strings.ToUpper(mac), ":", "")
}

var decryptionKeys = make(map[string][]byte)

func decryptData(data []byte, frameMac string, rssi int) {
	if len(data) < 11+3+4 {
		return
	}

	mac := fmt.Sprintf("%X", []byte{
		data[10], data[9], data[8], data[7], data[6], data[5],
	})

	if mac != frameMac {
		return
	}

	key, ok := decryptionKeys[mac]
	if !ok {
		log.Printf("no key for MAC %s, skipped\n", mac)
		return
	}

	ciphertext := []byte{}
	ciphertext = append(ciphertext, data[11:len(data)-7]...) // payload
	ciphertext = append(ciphertext, data[len(data)-4:]...)   // token

	nonce := []byte{}
	nonce = append(nonce, data[5:11]...)                    // reverse MAC
	nonce = append(nonce, data[2:5]...)                     // sensor type
	nonce = append(nonce, data[len(data)-7:len(data)-4]...) // counter

	aes, err := aes.NewCipher(key[:])
	if err != nil {
		log.Print("aes.NewCipher: ", err)
		return
	}
	ccm, err := aesccm.NewCCM(aes, 4, 12)
	if err != nil {
		log.Fatal("aesccm.NewCCM: ", err)
	}

	var Aad = []byte{0x11}

	dst, err := ccm.Open([]byte{}, nonce, ciphertext, Aad)
	if err != nil {
		log.Print("couldn't decrypt: ", err)
		return
	}

	bump(mac, ExpiryStock)

	if dst[0] == 0x04 { // temperature
		temp := float64(binary.LittleEndian.Uint16(dst[3:5])) / 10.0
		logTemperature(mac, temp)

	}
	if dst[0] == 0x06 { // humidity
		hum := float64(binary.LittleEndian.Uint16(dst[3:5])) / 10.0
		logHumidity(mac, hum)
	}
	if dst[0] == 0x0A { // battery
		// XXX always 100%?
		batp := float64(dst[3])
		logBatteryPercent(mac, batp)
	}

	rssiGauge.WithLabelValues(Sensor, mac).Set(float64(rssi))
}

func decodeSign(i uint16) int {
	if i < 32768 {
		return int(i)
	} else {
		return int(i) - 65536
	}
}

func registerData(data []byte, frameMac string, rssi int) {
	var sd sensorData
	var err error
	switch len(data) {
	case 13:
		sd, err = decodeATCData(data, frameMac)
		if err != nil {
			log.Print(err)
			return
		}
	case 15:
		sd, err = decodePVVXData(data, frameMac)
		if err != nil {
			log.Print(err)
			return
		}
	default:
		log.Printf("unknown data length %d\n", len(data))
		return
	}

	bump(sd.mac, ExpiryAtc)

	logTemperature(sd.mac, sd.temp)
	logHumidity(sd.mac, sd.hum)
	logBatteryPercent(sd.mac, sd.batp)
	logVoltage(sd.mac, sd.batv)

	frameGauge.WithLabelValues(Sensor, sd.mac).Set(sd.frame)
	rssiGauge.WithLabelValues(Sensor, sd.mac).Set(float64(rssi))
}

type sensorData struct {
	mac   string
	temp  float64
	hum   float64
	batp  float64
	batv  float64
	frame float64
}

func decodeATCData(data []byte, frameMac string) (sensorData, error) {
	if len(data) != 13 {
		return sensorData{}, fmt.Errorf("invalid data length %d", len(data))
	}
	mac := fmt.Sprintf("%X", data[0:6])
	if mac != frameMac {
		return sensorData{}, fmt.Errorf("MAC mismatch %s != %s", mac, frameMac)
	}

	return sensorData{
		mac:   mac,
		temp:  float64(decodeSign(binary.BigEndian.Uint16(data[6:8]))) / 10.0,
		hum:   float64(data[8]),
		batp:  float64(data[9]),
		batv:  float64(binary.BigEndian.Uint16(data[10:12])) / 1000.0,
		frame: float64(data[12]),
	}, nil
}

func decodePVVXData(data []byte, frameMac string) (sensorData, error) {
	if len(data) != 15 {
		return sensorData{}, fmt.Errorf("invalid data length %d", len(data))
	}
	var mac string
	for i := 5; i >= 0; i-- {
		mac += fmt.Sprintf("%02X", data[i])
	}
	if mac != frameMac {
		return sensorData{}, fmt.Errorf("MAC mismatch %s != %s", mac, frameMac)
	}
	return sensorData{
		mac:   mac,
		temp:  float64(decodeSign(binary.LittleEndian.Uint16(data[6:8]))) / 100.0,
		hum:   float64(decodeSign(binary.LittleEndian.Uint16(data[8:10]))) / 100.0,
		batv:  float64(binary.LittleEndian.Uint16(data[10:12])) / 1000.0,
		batp:  float64(data[12]),
		frame: float64(data[13]),
	}, nil
	// flags := float64(data[14])
}

func advHandler(a ble.Advertisement) {
	mac := strings.ReplaceAll(strings.ToUpper(a.Addr().String()), ":", "")

	for _, sd := range a.ServiceData() {
		if sd.UUID.Equal(EnvironmentalSensingUUID) {
			registerData(sd.Data, mac, a.RSSI())
		} else if sd.UUID.Equal(XiaomiIncUUID) {
			decryptData(sd.Data, mac, a.RSSI())
		} else {
			log.Printf("unknown service data: %s\n", sd.UUID)
		}
	}
}

func loadKeys(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, " ", 2)
		if len(fields[0]) != 12 || len(fields[1]) != 32 {
			log.Print("invalid config line, ignored: ", line)
			continue
		}
		mac := fields[0]
		key, err := hex.DecodeString(fields[1])
		if err != nil {
			log.Print("invalid config line, ignored: ", line)
			continue
		}
		decryptionKeys[mac] = key
	}
}

func logTemperature(mac string, temp float64) {
	tempGauge.WithLabelValues(Sensor, mac).Set(temp)
	log.Printf("%s thermometer_temperature_celsius %.1f\n", mac, temp)
}

func logHumidity(mac string, hum float64) {
	humGauge.WithLabelValues(Sensor, mac).Set(hum)
	log.Printf("%s thermometer_humidity_ratio %.0f\n", mac, hum)
}

func logVoltage(mac string, batv float64) {
	voltGauge.WithLabelValues(Sensor, mac).Set(batv)
	log.Printf("%s thermometer_battery_volts %.3f\n", mac, batv)
}

func logBatteryPercent(mac string, batp float64) {
	battGauge.WithLabelValues(Sensor, mac).Set(batp)
	log.Printf("%s thermometer_battery_ratio %.0f\n", mac, batp)
}

func decodeStockCharacteristic(mac string) func(req []byte) {
	return func(req []byte) {
		temp := float64(int(binary.LittleEndian.Uint16(req[0:2]))) / 100.0
		hum := float64(req[2])
		batv := float64(int(binary.LittleEndian.Uint16(req[3:5]))) / 1000.0

		bump(mac, ExpiryConn)

		logTemperature(mac, temp)
		logHumidity(mac, hum)
		logVoltage(mac, batv)
	}
}

func decodeAtcTemp(mac string) func(req []byte) {
	return func(req []byte) {
		temp := float64(decodeSign(binary.LittleEndian.Uint16(req[0:2]))) / 10.0
		bump(mac, ExpiryConn)
		logTemperature(mac, temp)
	}
}

func decodeAtcHumidity(mac string) func(req []byte) {
	return func(req []byte) {
		hum := float64(binary.LittleEndian.Uint16(req[0:2])) / 100.0
		bump(mac, ExpiryConn)
		logHumidity(mac, hum)
	}
}

func decodeAtcBattery(mac string) func(req []byte) {
	return func(req []byte) {
		batp := float64(req[0])
		bump(mac, ExpiryConn)
		logBatteryPercent(mac, batp)
	}
}

func pollData(mac string) {
	mac = macWithoutColons(mac)

	ctx := ble.WithSigHandler(context.WithTimeout(context.Background(), 50*time.Second))

	client, err := ble.Dial(ctx, ble.NewAddr(macWithColons(mac)))
	if err != nil {
		log.Fatal("oops: ", err)
	}
	profile, err := client.DiscoverProfile(true)
	if err != nil {
		log.Fatal("oops: ", err)
	}

	// code for stock hardware

	clientCharacteristicConfiguration := ble.MustParse("00002902-0000-1000-8000-00805f9b34fb")
	if c := profile.FindCharacteristic(ble.NewCharacteristic(clientCharacteristicConfiguration)); c != nil {
		b := []byte{0x01, 0x00}
		err := client.WriteCharacteristic(c, b, false)
		fmt.Printf("%v\n", err)
	}

	stockDataCharacteristic := ble.MustParse("ebe0ccc1-7a0a-4b0c-8a1a-6ff2997da3a6")
	if c := profile.FindCharacteristic(ble.NewCharacteristic(stockDataCharacteristic)); c != nil {
		err := client.Subscribe(c, false, decodeStockCharacteristic(mac))
		if err != nil {
			log.Print(err)
		}
	}

	// code for custom hardware

	batteryServiceBatteryLevel := ble.UUID16(0x2a19)
	if c := profile.FindCharacteristic(ble.NewCharacteristic(batteryServiceBatteryLevel)); c != nil {
		err := client.Subscribe(c, false, decodeAtcBattery(mac))
		if err != nil {
			log.Print(err)
		}
	}

	environmentalSensingTemperatureCelsius := ble.UUID16(0x2a1f)
	if c := profile.FindCharacteristic(ble.NewCharacteristic(environmentalSensingTemperatureCelsius)); c != nil {
		err := client.Subscribe(c, false, decodeAtcTemp(mac))
		if err != nil {
			log.Print(err)
		}
	}

	environmentalSensingHumidity := ble.UUID16(0x2a6f)
	if c := profile.FindCharacteristic(ble.NewCharacteristic(environmentalSensingHumidity)); c != nil {
		err := client.Subscribe(c, false, decodeAtcHumidity(mac))
		if err != nil {
			log.Print(err)
		}
	}
}

func main() {
	config := flag.String("k", "", "load keys from `file`")
	listenAddr := flag.String("l", ":9265", "listen on `addr`")
	deviceID := flag.Int("i", 0, "use device hci`N`")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [FLAGS...] [MACS TO POLL...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *config != "" {
		loadKeys(*config)
	}

	device, err := dev.NewDevice("default", ble.OptDeviceID(*deviceID))
	if err != nil {
		log.Fatal("oops: ", err)
	}

	ble.SetDefaultDevice(device)

	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>lywsd03mmc-exporter</title></head><body><h1>lywsd03mmc-exporter</h1><p><a href="/metrics">Metrics</a></p></body></html>`))
		})
		http.Handle("/metrics", promhttp.Handler())
		log.Println("Prometheus metrics listening on", *listenAddr)
		err := http.ListenAndServe(*listenAddr, nil)
		if err != http.ErrServerClosed {
			log.Fatal(err)
			os.Exit(1)
		}
	}()

	for _, mac := range flag.Args() {
		go pollData(mac)
	}

	ctx := ble.WithSigHandler(context.Background(), nil)

	telinkVendorFilter := func(a ble.Advertisement) bool {
		return strings.HasPrefix(a.Addr().String(), TelinkVendorPrefix)
	}
	err = ble.Scan(ctx, true, advHandler, telinkVendorFilter)
	if err != nil {
		log.Fatalf("oops: %s", err)
	}
}
