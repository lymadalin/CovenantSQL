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

package blockproducer

import (
	"bytes"
	"database/sql"
	"encoding/binary"

	pi "github.com/CovenantSQL/CovenantSQL/blockproducer/interfaces"
	"github.com/CovenantSQL/CovenantSQL/crypto/hash"
	"github.com/CovenantSQL/CovenantSQL/types"
	"github.com/CovenantSQL/CovenantSQL/utils"
	"github.com/pkg/errors"
)

// State store the node info of chain.
type State struct {
	Node   *blockNode
	Head   hash.Hash
	Height uint32
}

// EncodePayload implements EncodePayload of kayak/types.Handler.
func (_ *Chain) EncodePayload(request interface{}) (data []byte, err error) {
	var (
		ierr error
		t    uint32
		w    interface{}
	)
	switch r := request.(type) {
	case *types.Block:
		t = uint32(types.ChainOPTypeProduceBlock)
		w = r
	case pi.Transaction:
		t = uint32(types.ChainOPTypeAddTx)
		w = pi.WrapTransaction(r)
	default:
		err = errors.Wrapf(ErrUnknownChainOPType, "%v", request)
		return
	}

	var buff *bytes.Buffer
	if ierr = binary.Write(buff, binary.BigEndian, t); ierr != nil {
		err = errors.Wrap(ierr, "failed to write OP code")
		return
	}
	if ierr = utils.EncodeMsgPackToBuffer(buff, w); ierr != nil {
		err = errors.Wrap(ierr, "failed to encode payload")
		return
	}

	data = buff.Bytes()
	return
}

// DecodePayload implements DecodePayload of kayak/types.Handler.
func (_ *Chain) DecodePayload(data []byte) (request interface{}, err error) {
	var (
		ierr error
		t    uint32

		buff = bytes.NewReader(data)
	)
	if ierr = binary.Read(buff, binary.BigEndian, &t); ierr != nil {
		err = errors.Wrap(ierr, "failed to read OP code")
		return
	}

	switch types.ChainOPType(t) {
	case types.ChainOPTypeAddTx:
		request = new(pi.TransactionWrapper)
	case types.ChainOPTypeProduceBlock:
		request = new(types.Block)
	default:
		err = errors.Wrapf(ErrUnknownChainOPType, "%d", t)
		return
	}

	if ierr = utils.DecodeMsgPackFromBuffer(buff, request); ierr != nil {
		err = errors.Wrap(ierr, "failed to decode payload")
		return
	}
	for x, ok := request.(*pi.TransactionWrapper); ok; x, ok = request.(*pi.TransactionWrapper) {
		request = x.Unwrap()
	}

	return
}

// Check implements Check of kayak/types.Handler.
func (c *Chain) Check(rawReq interface{}) (err error) {
	var ierr error
	switch r := rawReq.(type) {
	case *types.Block:
		if ierr = r.Verify(); ierr != nil {
			err = errors.Wrap(err, "failed to verify block")
			return
		}
	case pi.Transaction:
		if ierr = r.Verify(); ierr != nil {
			err = errors.Wrap(err, "failed to verify transaction")
			return
		}
	default:
		err = errors.Wrapf(ErrUnknownChainOPType, "%v", rawReq)
		return
	}
	return
}

// Commit implements Commit of kayak/types.Handler.
func (c *Chain) Commit(rawReq interface{}) (result interface{}, err error) {
	var (
		ierr error
		qs   []*types.Query
	)
	switch r := rawReq.(type) {
	case *types.Block:
		if qs, ierr = BlockToQueries(r); ierr != nil {
			return
		}
	case pi.Transaction:
	default:
		err = errors.Wrapf(ErrUnknownChainOPType, "%v", rawReq)
		return
	}
	var tx *sql.Tx
	if tx, ierr = c.st.Writer().Begin(); ierr != nil {
		err = errors.Wrap(ierr, "failed to begin sql.Tx")
		return
	}
	defer tx.Rollback()
	for i, q := range qs {
		var args = make([]interface{}, len(q.Args))
		for j, v := range q.Args {
			args[j] = sql.NamedArg{
				Name:  v.Name,
				Value: v.Value,
			}
		}
		if _, ierr = tx.Exec(q.Pattern, args...); ierr != nil {
			err = errors.Wrapf(ierr, "failed to execute at #%d", i)
			return
		}
	}
	if ierr = tx.Commit(); ierr != nil {
		err = errors.Wrap(ierr, "failed to commit sql.Tx")
		return
	}
	return
}

func BlockToQueries(b *types.Block) (qs []*types.Query, err error) {
	return
}
