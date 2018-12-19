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

package worker

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CovenantSQL/CovenantSQL/proto"
	"github.com/CovenantSQL/CovenantSQL/route"
	"github.com/CovenantSQL/CovenantSQL/rpc"
	"github.com/CovenantSQL/CovenantSQL/sqlchain"
	"github.com/CovenantSQL/CovenantSQL/types"
	"github.com/CovenantSQL/CovenantSQL/utils"
	"github.com/CovenantSQL/CovenantSQL/utils/log"
	"github.com/pkg/errors"
)

const (
	// DBKayakRPCName defines rpc service name of database internal consensus.
	DBKayakRPCName = "DBC" // aka. database consensus

	// DBMetaFileName defines dbms meta file name.
	DBMetaFileName = "db.meta"

	// DefaultSlowQueryTime defines the default slow query log time
	DefaultSlowQueryTime = time.Second * 5
)

// DBMS defines a database management instance.
type DBMS struct {
	cfg      *DBMSConfig
	dbMap    sync.Map
	kayakMux *DBKayakMuxService
	chainMux *sqlchain.MuxService
	rpc      *DBMSRPCService
}

// NewDBMS returns new database management instance.
func NewDBMS(cfg *DBMSConfig) (dbms *DBMS, err error) {
	dbms = &DBMS{
		cfg: cfg,
	}

	// init kayak rpc mux
	if dbms.kayakMux, err = NewDBKayakMuxService(DBKayakRPCName, cfg.Server); err != nil {
		err = errors.Wrap(err, "register kayak mux service failed")
		return
	}

	// init sql-chain rpc mux
	if dbms.chainMux, err = sqlchain.NewMuxService(route.SQLChainRPCName, cfg.Server); err != nil {
		err = errors.Wrap(err, "register sqlchain mux service failed")
		return
	}

	// init service
	dbms.rpc = NewDBMSRPCService(route.DBRPCName, cfg.Server, dbms)

	return
}

func (dbms *DBMS) readMeta() (meta *DBMSMeta, err error) {
	filePath := filepath.Join(dbms.cfg.RootDir, DBMetaFileName)
	meta = NewDBMSMeta()

	var fileContent []byte

	if fileContent, err = ioutil.ReadFile(filePath); err != nil {
		// if not exists
		if os.IsNotExist(err) {
			// new without meta
			err = nil
			return
		}

		return
	}

	err = utils.DecodeMsgPack(fileContent, meta)

	// create empty meta if meta map is nil
	if err == nil && meta.DBS == nil {
		meta = NewDBMSMeta()
	}

	return
}

func (dbms *DBMS) writeMeta() (err error) {
	meta := NewDBMSMeta()

	dbms.dbMap.Range(func(key, value interface{}) bool {
		dbID := key.(proto.DatabaseID)
		meta.DBS[dbID] = true
		return true
	})

	var buf *bytes.Buffer
	if buf, err = utils.EncodeMsgPack(meta); err != nil {
		return
	}

	filePath := filepath.Join(dbms.cfg.RootDir, DBMetaFileName)
	err = ioutil.WriteFile(filePath, buf.Bytes(), 0644)

	return
}

// Init defines dbms init logic.
func (dbms *DBMS) Init() (err error) {
	// read meta
	var localMeta *DBMSMeta
	if localMeta, err = dbms.readMeta(); err != nil {
		err = errors.Wrap(err, "read dbms meta failed")
		return
	}

	// load current peers info from block producer
	var dbMapping []types.ServiceInstance
	if dbMapping, err = dbms.getMappedInstances(); err != nil {
		err = errors.Wrap(err, "get mapped instances failed")
		return
	}

	// init database
	if err = dbms.initDatabases(localMeta, dbMapping); err != nil {
		err = errors.Wrap(err, "init databases with meta failed")
		return
	}

	return
}

func (dbms *DBMS) initDatabases(meta *DBMSMeta, conf []types.ServiceInstance) (err error) {
	currentInstance := make(map[proto.DatabaseID]bool)

	for _, instanceConf := range conf {
		currentInstance[instanceConf.DatabaseID] = true
		if err = dbms.Create(&instanceConf, false); err != nil {
			return
		}
	}

	// calculate to drop databases
	toDropInstance := make(map[proto.DatabaseID]bool)

	for dbID := range meta.DBS {
		if _, exists := currentInstance[dbID]; !exists {
			toDropInstance[dbID] = true
		}
	}

	// drop database
	for dbID := range toDropInstance {
		if err = dbms.Drop(dbID); err != nil {
			return
		}
	}

	return
}

// Create add new database to the miner dbms.
func (dbms *DBMS) Create(instance *types.ServiceInstance, cleanup bool) (err error) {
	if _, alreadyExists := dbms.getMeta(instance.DatabaseID); alreadyExists {
		return ErrAlreadyExists
	}

	// set database root dir
	rootDir := filepath.Join(dbms.cfg.RootDir, string(instance.DatabaseID))

	// clear current data
	if cleanup {
		if err = os.RemoveAll(rootDir); err != nil {
			return
		}
	}

	var db *Database

	defer func() {
		// close on failed
		if err != nil {
			if db != nil {
				db.Shutdown()
			}

			dbms.removeMeta(instance.DatabaseID)
		}
	}()

	// new db
	dbCfg := &DBConfig{
		DatabaseID:      instance.DatabaseID,
		DataDir:         rootDir,
		KayakMux:        dbms.kayakMux,
		ChainMux:        dbms.chainMux,
		MaxWriteTimeGap: dbms.cfg.MaxReqTimeGap,
		EncryptionKey:   instance.ResourceMeta.EncryptionKey,
		SpaceLimit:      instance.ResourceMeta.Space,
		SlowQueryTime:   DefaultSlowQueryTime,
	}

	if db, err = NewDatabase(dbCfg, instance.Peers, instance.GenesisBlock); err != nil {
		return
	}

	// add to meta
	err = dbms.addMeta(instance.DatabaseID, db)

	return
}

// Drop remove database from the miner dbms.
func (dbms *DBMS) Drop(dbID proto.DatabaseID) (err error) {
	var db *Database
	var exists bool

	if db, exists = dbms.getMeta(dbID); !exists {
		return ErrNotExists
	}

	// shutdown database
	if err = db.Destroy(); err != nil {
		return
	}

	// remove meta
	return dbms.removeMeta(dbID)
}

// Update apply the new peers config to dbms.
func (dbms *DBMS) Update(instance *types.ServiceInstance) (err error) {
	var db *Database
	var exists bool

	if db, exists = dbms.getMeta(instance.DatabaseID); !exists {
		return ErrNotExists
	}

	// update peers
	return db.UpdatePeers(instance.Peers)
}

// Query handles query request in dbms.
func (dbms *DBMS) Query(req *types.Request) (res *types.Response, err error) {
	var db *Database
	var exists bool

	// find database
	if db, exists = dbms.getMeta(req.Header.DatabaseID); !exists {
		err = ErrNotExists
		return
	}

	// send query
	return db.Query(req)
}

// Ack handles ack of previous response.
func (dbms *DBMS) Ack(ack *types.Ack) (err error) {
	var db *Database
	var exists bool

	// find database
	if db, exists = dbms.getMeta(ack.Header.Response.Request.DatabaseID); !exists {
		err = ErrNotExists
		return
	}

	// send query
	return db.Ack(ack)
}

func (dbms *DBMS) getMeta(dbID proto.DatabaseID) (db *Database, exists bool) {
	var rawDB interface{}

	if rawDB, exists = dbms.dbMap.Load(dbID); !exists {
		return
	}

	db = rawDB.(*Database)

	return
}

func (dbms *DBMS) addMeta(dbID proto.DatabaseID, db *Database) (err error) {
	if _, alreadyExists := dbms.dbMap.LoadOrStore(dbID, db); alreadyExists {
		return ErrAlreadyExists
	}

	return dbms.writeMeta()
}

func (dbms *DBMS) removeMeta(dbID proto.DatabaseID) (err error) {
	dbms.dbMap.Delete(dbID)
	return dbms.writeMeta()
}

func (dbms *DBMS) getMappedInstances() (instances []types.ServiceInstance, err error) {
	var bpNodeID proto.NodeID
	if bpNodeID, err = rpc.GetCurrentBP(); err != nil {
		return
	}

	req := &types.InitService{}
	res := new(types.InitServiceResponse)

	if err = rpc.NewCaller().CallNode(bpNodeID, route.BPDBGetNodeDatabases.String(), req, res); err != nil {
		return
	}

	// verify response
	if err = res.Verify(); err != nil {
		return
	}

	instances = res.Header.Instances

	return
}

// Shutdown defines dbms shutdown logic.
func (dbms *DBMS) Shutdown() (err error) {
	dbms.dbMap.Range(func(_, rawDB interface{}) bool {
		db := rawDB.(*Database)

		if err = db.Shutdown(); err != nil {
			log.WithError(err).Error("shutdown database failed")
		}

		return true
	})

	// persist meta
	err = dbms.writeMeta()

	return
}
