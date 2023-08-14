// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/datatransfers/data_transfers.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	pgx "github.com/jackc/pgx/v5"
	gomock "go.uber.org/mock/gomock"
)

// MockpgxConnIface is a mock of pgxConnIface interface.
type MockpgxConnIface struct {
	ctrl     *gomock.Controller
	recorder *MockpgxConnIfaceMockRecorder
}

// MockpgxConnIfaceMockRecorder is the mock recorder for MockpgxConnIface.
type MockpgxConnIfaceMockRecorder struct {
	mock *MockpgxConnIface
}

// NewMockpgxConnIface creates a new mock instance.
func NewMockpgxConnIface(ctrl *gomock.Controller) *MockpgxConnIface {
	mock := &MockpgxConnIface{ctrl: ctrl}
	mock.recorder = &MockpgxConnIfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockpgxConnIface) EXPECT() *MockpgxConnIfaceMockRecorder {
	return m.recorder
}

// Begin mocks base method.
func (m *MockpgxConnIface) Begin(arg0 context.Context) (pgx.Tx, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Begin", arg0)
	ret0, _ := ret[0].(pgx.Tx)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Begin indicates an expected call of Begin.
func (mr *MockpgxConnIfaceMockRecorder) Begin(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Begin", reflect.TypeOf((*MockpgxConnIface)(nil).Begin), arg0)
}

// BeginTx mocks base method.
func (m *MockpgxConnIface) BeginTx(arg0 context.Context, arg1 pgx.TxOptions) (pgx.Tx, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BeginTx", arg0, arg1)
	ret0, _ := ret[0].(pgx.Tx)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BeginTx indicates an expected call of BeginTx.
func (mr *MockpgxConnIfaceMockRecorder) BeginTx(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BeginTx", reflect.TypeOf((*MockpgxConnIface)(nil).BeginTx), arg0, arg1)
}

// Close mocks base method.
func (m *MockpgxConnIface) Close(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockpgxConnIfaceMockRecorder) Close(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockpgxConnIface)(nil).Close), arg0)
}