// lywsd03mmc-exporter - a Prometheus exporter for the LYWSD03MMC BLE thermometer

// Copyright (C) 2015-2020 Leah Neukirchen <leah@vuxu.org>
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
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"crypto/aes"
	"github.com/pschlump/AesCCM"
)

var (
	tempGauge = prometheus.NewGaugeVec(
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
	humGauge = prometheus.NewGaugeVec(
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
	battGauge = prometheus.NewGaugeVec(
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
	voltGauge = prometheus.NewGaugeVec(
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
	frameGauge = prometheus.NewGaugeVec(
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
	rssiGauge = prometheus.NewGaugeVec(
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
		log.Printf("%s thermometer_temperature_celsius %.1f\n", mac, temp)
		tempGauge.WithLabelValues(Sensor, mac).Set(temp)

	}
	if dst[0] == 0x06 { // humidity
		hum := float64(binary.LittleEndian.Uint16(dst[3:5])) / 10.0
		log.Printf("%s thermometer_humidity_ratio %.0f\n", mac, hum)
		humGauge.WithLabelValues(Sensor, mac).Set(hum)
	}
	if dst[0] == 0x0A { // battery
		// XXX always 100%?
		bat := float64(dst[3])
		log.Printf("%s thermometer_battery_ratio %.0f\n", mac, bat)
		battGauge.WithLabelValues(Sensor, mac).Set(bat)
	}

	rssiGauge.WithLabelValues(Sensor, mac).Set(float64(rssi))
}

func registerData(data []byte, frameMac string, rssi int) {
	if len(data) != 13 {
		return
	}

	mac := fmt.Sprintf("%X", data[0:6])

	if mac != frameMac {
		return
	}

	temp := float64(binary.BigEndian.Uint16(data[6:8])) / 10.0
	hum := float64(data[8])
	batp := float64(data[9])
	batv := float64(binary.BigEndian.Uint16(data[10:12])) / 1000.0
	frame := float64(data[12])

	bump(mac, ExpiryAtc)

	tempGauge.WithLabelValues(Sensor, mac).Set(temp)
	humGauge.WithLabelValues(Sensor, mac).Set(hum)
	battGauge.WithLabelValues(Sensor, mac).Set(batp)
	voltGauge.WithLabelValues(Sensor, mac).Set(batv)
	frameGauge.WithLabelValues(Sensor, mac).Set(frame)
	rssiGauge.WithLabelValues(Sensor, mac).Set(float64(rssi))

	log.Printf("%s thermometer_temperature_celsius %.1f\n", mac, temp)
	log.Printf("%s thermometer_humidity_ratio %.0f\n", mac, hum)
	log.Printf("%s thermometer_battery_ratio %.0f\n", mac, batp)
	log.Printf("%s thermometer_battery_volts %.3f\n", mac, batv)
	log.Printf("%s thermometer_frame_current %.0f\n", mac, frame)
}

func advHandler(a ble.Advertisement) {
	mac := strings.ReplaceAll(strings.ToUpper(a.Addr().String()), ":", "")

	for _, sd := range a.ServiceData() {
		if sd.UUID.Equal(EnvironmentalSensingUUID) {
			registerData(sd.Data, mac, a.RSSI())
		}
		if sd.UUID.Equal(XiaomiIncUUID) {
			decryptData(sd.Data, mac, a.RSSI())
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

func main() {

	config := flag.String("k", "", "load keys from `file`")
	listenAddr := flag.String("l", ":9265", "listen on `addr`")
	deviceID := flag.Int("i", 0, "use device hci`N`")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [FLAGS...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if (*config != "") {
		loadKeys(*config)
	}

	device, err := dev.NewDevice("default", ble.OptDeviceID(*deviceID))
	if err != nil {
		log.Fatal("oops: ", err)
	}

	ble.SetDefaultDevice(device)

	prometheus.MustRegister(tempGauge)
	prometheus.MustRegister(humGauge)
	prometheus.MustRegister(battGauge)
	prometheus.MustRegister(voltGauge)
	prometheus.MustRegister(frameGauge)
	prometheus.MustRegister(rssiGauge)

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

	ctx := ble.WithSigHandler(context.Background(), nil)

	telinkVendorFilter := func(a ble.Advertisement) bool {
		return strings.HasPrefix(a.Addr().String(), TelinkVendorPrefix)
	}
	err = ble.Scan(ctx, true, advHandler, telinkVendorFilter)
	if err != nil {
		log.Fatal("oops: %s", err)
	}
}
