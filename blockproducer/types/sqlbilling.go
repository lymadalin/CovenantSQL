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

package types

import (
	pi "github.com/CovenantSQL/CovenantSQL/blockproducer/interfaces"
	"github.com/CovenantSQL/CovenantSQL/crypto/asymmetric"
	"github.com/CovenantSQL/CovenantSQL/proto"
	"github.com/CovenantSQL/CovenantSQL/sqlchain/types"
)

//go:generate hsp

// SQLBillingHeader defines the sql billing header.
type SQLBillingHeader struct {
	TargetSQLChain proto.AccountAddress
	Headers []types.SignedHeader
	Nonce pi.AccountNonce
}

// SQLBilling defines the sql billing.
type SQLBilling struct {
	SQLBillingHeader
	pi.TransactionTypeMixin
	DefaultHashSignVerifierImpl
}

// NewSQLBilling returns new instance.
func NewSQLBilling(header *SQLBillingHeader) *SQLBilling {
	return &SQLBilling{
		SQLBillingHeader: *header,
		TransactionTypeMixin: *pi.NewTransactionTypeMixin(pi.TransactionTypeSQLBilling),
	}
}

// GetAccountAddress implements interfaces/Transaction.GetAccountAddress.
func (s *SQLBilling) GetAccountAddress() proto.AccountAddress {
	return s.TargetSQLChain
}

// GetAccountNonce implements interfaces/Transaction.GetAccountNonce.
func (s *SQLBilling) GetAccountNonce() pi.AccountNonce {
	return s.Nonce
}

// Sign implements interfaces/Transaction.Sign.
func (s *SQLBilling) Sign(signer *asymmetric.PrivateKey) (err error) {
	return s.DefaultHashSignVerifierImpl.Sign(&s.SQLBillingHeader, signer)
}

// Verify implements interfaces/Transaction.Verify.
func (s *SQLBilling) Verify() (err error) {
	return s.DefaultHashSignVerifierImpl.Verify(&s.SQLBillingHeader)
}

func init() {
	pi.RegisterTransaction(pi.TransactionTypeSQLBilling, (*SQLBilling)(nil))
}
