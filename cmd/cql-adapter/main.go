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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/CovenantSQL/CovenantSQL/crypto/asymmetric"
	"github.com/CovenantSQL/CovenantSQL/utils/log"
	"golang.org/x/sys/unix"
)

const name = "cql-adapeter"

var (
	version     = "unknown"
	configFile  string
	password    string
	showVersion bool
)

func init() {
	flag.StringVar(&configFile, "config", "./config.yaml", "config file for adapter")
	flag.StringVar(&password, "password", "", "master key password")
	flag.BoolVar(&asymmetric.BypassSignature, "bypassSignature", false,
		"Disable signature sign and verify, for testing")
	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
}

func main() {
	flag.Parse()
	if showVersion {
		fmt.Printf("%v %v %v %v %v\n",
			name, version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		os.Exit(0)
	}

	flag.Visit(func(f *flag.Flag) {
		log.Infof("Args %#v : %s", f.Name, f.Value)
	})

	server, err := NewHTTPAdapter(configFile, password)
	if err != nil {
		log.WithError(err).Fatal("init adapter failed")
		return
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, unix.SIGTERM)

	log.Info("start adapter")
	if err = server.Serve(); err != nil {
		log.WithError(err).Fatal("start adapter failed")
		return
	}

	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	server.Shutdown(ctx)
	log.Info("stopped adapter")
}
