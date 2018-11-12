package otypes

// Code generated by github.com/CovenantSQL/HashStablePack DO NOT EDIT.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestMarshalHashInitService(t *testing.T) {
	v := InitService{}
	binary.Read(rand.Reader, binary.BigEndian, &v)
	bts1, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	bts2, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bts1, bts2) {
		t.Fatal("hash not stable")
	}
}

func BenchmarkMarshalHashInitService(b *testing.B) {
	v := InitService{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.MarshalHash()
	}
}

func BenchmarkAppendMsgInitService(b *testing.B) {
	v := InitService{}
	bts := make([]byte, 0, v.Msgsize())
	bts, _ = v.MarshalHash()
	b.SetBytes(int64(len(bts)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bts, _ = v.MarshalHash()
	}
}

func TestMarshalHashInitServiceResponse(t *testing.T) {
	v := InitServiceResponse{}
	binary.Read(rand.Reader, binary.BigEndian, &v)
	bts1, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	bts2, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bts1, bts2) {
		t.Fatal("hash not stable")
	}
}

func BenchmarkMarshalHashInitServiceResponse(b *testing.B) {
	v := InitServiceResponse{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.MarshalHash()
	}
}

func BenchmarkAppendMsgInitServiceResponse(b *testing.B) {
	v := InitServiceResponse{}
	bts := make([]byte, 0, v.Msgsize())
	bts, _ = v.MarshalHash()
	b.SetBytes(int64(len(bts)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bts, _ = v.MarshalHash()
	}
}

func TestMarshalHashInitServiceResponseHeader(t *testing.T) {
	v := InitServiceResponseHeader{}
	binary.Read(rand.Reader, binary.BigEndian, &v)
	bts1, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	bts2, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bts1, bts2) {
		t.Fatal("hash not stable")
	}
}

func BenchmarkMarshalHashInitServiceResponseHeader(b *testing.B) {
	v := InitServiceResponseHeader{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.MarshalHash()
	}
}

func BenchmarkAppendMsgInitServiceResponseHeader(b *testing.B) {
	v := InitServiceResponseHeader{}
	bts := make([]byte, 0, v.Msgsize())
	bts, _ = v.MarshalHash()
	b.SetBytes(int64(len(bts)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bts, _ = v.MarshalHash()
	}
}

func TestMarshalHashResourceMeta(t *testing.T) {
	v := ResourceMeta{}
	binary.Read(rand.Reader, binary.BigEndian, &v)
	bts1, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	bts2, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bts1, bts2) {
		t.Fatal("hash not stable")
	}
}

func BenchmarkMarshalHashResourceMeta(b *testing.B) {
	v := ResourceMeta{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.MarshalHash()
	}
}

func BenchmarkAppendMsgResourceMeta(b *testing.B) {
	v := ResourceMeta{}
	bts := make([]byte, 0, v.Msgsize())
	bts, _ = v.MarshalHash()
	b.SetBytes(int64(len(bts)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bts, _ = v.MarshalHash()
	}
}

func TestMarshalHashServiceInstance(t *testing.T) {
	v := ServiceInstance{}
	binary.Read(rand.Reader, binary.BigEndian, &v)
	bts1, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	bts2, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bts1, bts2) {
		t.Fatal("hash not stable")
	}
}

func BenchmarkMarshalHashServiceInstance(b *testing.B) {
	v := ServiceInstance{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.MarshalHash()
	}
}

func BenchmarkAppendMsgServiceInstance(b *testing.B) {
	v := ServiceInstance{}
	bts := make([]byte, 0, v.Msgsize())
	bts, _ = v.MarshalHash()
	b.SetBytes(int64(len(bts)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bts, _ = v.MarshalHash()
	}
}

func TestMarshalHashSignedInitServiceResponseHeader(t *testing.T) {
	v := SignedInitServiceResponseHeader{}
	binary.Read(rand.Reader, binary.BigEndian, &v)
	bts1, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	bts2, err := v.MarshalHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bts1, bts2) {
		t.Fatal("hash not stable")
	}
}

func BenchmarkMarshalHashSignedInitServiceResponseHeader(b *testing.B) {
	v := SignedInitServiceResponseHeader{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.MarshalHash()
	}
}

func BenchmarkAppendMsgSignedInitServiceResponseHeader(b *testing.B) {
	v := SignedInitServiceResponseHeader{}
	bts := make([]byte, 0, v.Msgsize())
	bts, _ = v.MarshalHash()
	b.SetBytes(int64(len(bts)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bts, _ = v.MarshalHash()
	}
}