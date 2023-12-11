// lywsd03mmc-exporter - a Prometheus exporter for the LYWSD03MMC BLE thermometer

// Copyright (C) 2020 Leah Neukirchen <leah@vuxu.org>
// Licensed under the terms of the MIT license, see LICENSE.

package main

import (
	"reflect"
	"strings"
	"testing"
)

func Test_decodeATCData(t *testing.T) {
	type args struct {
		data     []byte
		frameMac string
	}
	tests := []struct {
		name    string
		args    args
		want    sensorData
		wantErr bool
	}{
		{
			name: "valid data",
			args: args{
				data:     []byte{0x4c, 0x59, 0x57, 0x53, 0x44, 0x30, 0x01, 0x0c, 0x35, 0x64, 0x0b, 0xb8, 0x7b},
				frameMac: "4C:59:57:53:44:30",
			},
			want: sensorData{
				mac:   "4C5957534430",
				temp:  26.8,
				hum:   53,
				batp:  100,
				batv:  3,
				frame: 123,
			},
			wantErr: false,
		},
		{
			name: "valid date with wrong frameMac",
			args: args{
				data:     []byte{0x4c, 0x59, 0x57, 0x53, 0x44, 0x30, 0x01, 0x0c, 0x35, 0x64, 0x0b, 0xb8, 0x7b},
				frameMac: "4C:59:57:53:44:31",
			},
			wantErr: true,
		},
		{
			name: "invalid data",
			args: args{
				data:     []byte{0x4c, 0x59, 0x57, 0x53, 0x44, 0x30, 0x01, 0x0c, 0x35, 0x64, 0x0b, 0xb8},
				frameMac: "4C:59:57:53:44:30",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frameMac := strings.ReplaceAll(strings.ToUpper(tt.args.frameMac), ":", "")
			got, err := decodeATCData(tt.args.data, frameMac)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeATCData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeATCData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodePVVXData(t *testing.T) {
	type args struct {
		data     []byte
		frameMac string
	}
	tests := []struct {
		name    string
		args    args
		want    sensorData
		wantErr bool
	}{
		{
			name: "valid data",
			args: args{
				data:     []byte{0x30, 0x44, 0x53, 0x57, 0x59, 0x4c, 0x78, 0x0a, 0xb4, 0x14, 0xb8, 0x0b, 0x64, 0x7b, 0x0},
				frameMac: "4C:59:57:53:44:30",
			},
			want: sensorData{
				mac:   "4C5957534430",
				temp:  26.8,
				hum:   53,
				batp:  100,
				batv:  3,
				frame: 123,
			},
			wantErr: false,
		},
		{
			name: "valid date with wrong frameMac",
			args: args{
				data:     []byte{0x30, 0x44, 0x53, 0x57, 0x59, 0x4c, 0x78, 0x0a, 0xb4, 0x14, 0xb8, 0x0b, 0x64, 0x7b, 0x0},
				frameMac: "4C:59:57:53:44:31",
			},
			wantErr: true,
		},
		{
			name: "invalid data",
			args: args{
				data:     []byte{0x30, 0x44, 0x53, 0x57, 0x59, 0x4c, 0x78, 0x0a, 0xb4, 0x14, 0xb8, 0x0b, 0x64, 0x7b},
				frameMac: "4C:59:57:53:44:30",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frameMac := strings.ReplaceAll(strings.ToUpper(tt.args.frameMac), ":", "")
			got, err := decodePVVXData(tt.args.data, frameMac)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodePVVXData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodePVVXData() = %v, want %v", got, tt.want)
			}
		})
	}
}
