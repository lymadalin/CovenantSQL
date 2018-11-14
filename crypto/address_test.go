/*
 * Copyright 2018 The CovenantSQL Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/CovenantSQL/CovenantSQL/crypto/asymmetric"
	"github.com/CovenantSQL/CovenantSQL/crypto/hash"
	"github.com/CovenantSQL/CovenantSQL/proto"
	"github.com/btcsuite/btcutil/base58"
	. "github.com/smartystreets/goconvey/convey"
)

func TestPubKeyHashAndAddressing(t *testing.T) {
	testPubkeyAndAddr := []struct {
		pubkey  string
		addr    string
		nettype byte
	}{
		{
			pubkey:  "AwVygZRpvwCc+8SKnbwQrtlXPze7/hte0ksObyml37Gi",
			addr:    "1EcL9WYyB59jVLSX9kxFdfY53aDoWAKSFRkwwV2cvMMNCWj81J",
			nettype: MainNet,
		},
		{
			pubkey:  "AwVygZRpvwCc+8SKnbwQrtlXPze7/hte0ksObyml37Gi",
			addr:    "4j1EutL6ZQ9HhYqj9Ves8EDVihvvxfhWnCHi2ZqXxf6Q9GK45v5",
			nettype: TestNet,
		},
		{
			pubkey:  "Aua4icZ7gvBbzw4MDkGvFOEXG88lY4IJccigDQRghj1c",
			addr:    "12HRffwitkFR4ooMu6x5EAnHscKyftfuTZnTc3ciYmoSh9HxMY5",
			nettype: MainNet,
		},
		{
			pubkey:  "Aua4icZ7gvBbzw4MDkGvFOEXG88lY4IJccigDQRghj1c",
			addr:    "4k44FQmGUyKZ2sJeXSqz6mLFXGggq4D6oWeQgfyDtWYVUDQS2bj",
			nettype: TestNet,
		},
		{
			pubkey:  "An/n4w2Lb3QYPzpQjAlADcK14LnwDbkl21gdasuwND1a",
			addr:    "1FinCZcguUux4fxM5dJuuGCUNRTw49Dx26KnAzA8Kh4djuHeH2",
			nettype: MainNet,
		},
		{
			pubkey:  "An/n4w2Lb3QYPzpQjAlADcK14LnwDbkl21gdasuwND1a",
			addr:    "4j2MMwPAH8Z3v8BEyRXDnVpA82nB6DgRHxxGroLfU4S7Qk5k9vQ",
			nettype: TestNet,
		},
	}

	testDBIDAndInternalAddr := []struct {
		dbid         proto.DatabaseID
		internalAddr string
	}{
		{
			dbid:         "4j2MMwPAH8Z3v8BEyRXDnVpA82nB6DgRHxxGroLfU4S7Qk5k9vQ",
			internalAddr: "638e4c8b984a35ded9063a318428ae5d2e12459b48a9002a2f9683281f425d88",
		},
		{
			dbid:         "1FinCZcguUux4fxM5dJuuGCUNRTw49Dx26KnAzA8Kh4djuHeH2",
			internalAddr: "55d8f55a09ce5fd81e324665b99ebf24268e483bcf746996c045f7c2116b589c",
		},
		{
			dbid:         "4k44FQmGUyKZ2sJeXSqz6mLFXGggq4D6oWeQgfyDtWYVUDQS2bj",
			internalAddr: "dcbc0e17e5f2a720c3deebd3b7590c7333f897e2e079323146e15771cabd6989",
		},
		{
			dbid:         "12HRffwitkFR4ooMu6x5EAnHscKyftfuTZnTc3ciYmoSh9HxMY5",
			internalAddr: "74607a53571b845a1faa446459161b548984bc7fa15d8d7019419e06f48925c4",
		},
		{
			dbid:         "4j1EutL6ZQ9HhYqj9Ves8EDVihvvxfhWnCHi2ZqXxf6Q9GK45v5",
			internalAddr: "f8e086b14b7a6fc16623dc966e02a833b699c6f4aeba114aed609742a6505e40",
		},
		{
			dbid:         "1EcL9WYyB59jVLSX9kxFdfY53aDoWAKSFRkwwV2cvMMNCWj81J",
			internalAddr: "10b083120e427564a13db560c051c51e46c2861a8511f5d0ad050a4965a8d536",
		},
	}

	Convey("Test the public key and address", t, func() {
		for i := range testPubkeyAndAddr {
			pubByte, err := base64.StdEncoding.DecodeString(testPubkeyAndAddr[i].pubkey)
			So(err, ShouldBeNil)
			pub, err := asymmetric.ParsePubKey(pubByte)
			addr, err := PubKey2Addr(pub, testPubkeyAndAddr[i].nettype)
			So(addr, ShouldEqual, testPubkeyAndAddr[i].addr)
		}
	})

	Convey("Randomly generate some key pairs and calculate public key hash values", t, func() {
		for i := 0; i < 20; i++ {
			_, pub, err := asymmetric.GenSecp256k1KeyPair()
			So(err, ShouldBeNil)
			h, err := PubKeyHash(pub)
			So(err, ShouldBeNil)
			addr, err := PubKey2Addr(pub, MainNet)
			So(err, ShouldBeNil)
			targetAddr := base58.CheckEncode(h[:], MainNet)
			So(addr, ShouldEqual, targetAddr)
			t.Logf("main net address: %s", targetAddr)

			addr, err = PubKey2Addr(pub, TestNet)
			So(err, ShouldBeNil)
			targetAddr = base58.CheckEncode(h[:], TestNet)
			So(err, ShouldBeNil)
			t.Logf("test net address: %s", targetAddr)
		}
	})

	Convey("Test Hash/Addr bi-directional convert", t, func() {
		version, internalAddr, err := Addr2Hash("4j2MMwPAH8Z3v8BEyRXDnVpA82nB6DgRHxxGroLfU4S7Qk5k9vQ")
		So(version, ShouldEqual, TestNet)
		So(err, ShouldBeNil)

		addr := Hash2Addr(internalAddr, MainNet)
		So(addr, ShouldEqual, "1FinCZcguUux4fxM5dJuuGCUNRTw49Dx26KnAzA8Kh4djuHeH2")
	})

	Convey("Test Database ID to Hash", t, func() {
		for i := range testDBIDAndInternalAddr {
			addr := DBID2Hash(testDBIDAndInternalAddr[i].dbid)
			target, _ := hash.NewHashFromStr(testDBIDAndInternalAddr[i].internalAddr)
			So(addr[:], ShouldResemble, (*target)[:])
		}
	})
}
