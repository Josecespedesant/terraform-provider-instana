// Code generated by MockGen. DO NOT EDIT.
// Source: instana/restapi/tag-filter.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	restapi "github.com/gessnerfl/terraform-provider-instana/instana/restapi"
	gomock "go.uber.org/mock/gomock"
)

// MockTagFilterExpressionElement is a mock of TagFilterExpressionElement interface.
type MockTagFilterExpressionElement struct {
	ctrl     *gomock.Controller
	recorder *MockTagFilterExpressionElementMockRecorder
}

// MockTagFilterExpressionElementMockRecorder is the mock recorder for MockTagFilterExpressionElement.
type MockTagFilterExpressionElementMockRecorder struct {
	mock *MockTagFilterExpressionElement
}

// NewMockTagFilterExpressionElement creates a new mock instance.
func NewMockTagFilterExpressionElement(ctrl *gomock.Controller) *MockTagFilterExpressionElement {
	mock := &MockTagFilterExpressionElement{ctrl: ctrl}
	mock.recorder = &MockTagFilterExpressionElementMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTagFilterExpressionElement) EXPECT() *MockTagFilterExpressionElementMockRecorder {
	return m.recorder
}

// GetType mocks base method.
func (m *MockTagFilterExpressionElement) GetType() restapi.TagFilterExpressionElementType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetType")
	ret0, _ := ret[0].(restapi.TagFilterExpressionElementType)
	return ret0
}

// GetType indicates an expected call of GetType.
func (mr *MockTagFilterExpressionElementMockRecorder) GetType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetType", reflect.TypeOf((*MockTagFilterExpressionElement)(nil).GetType))
}

// Validate mocks base method.
func (m *MockTagFilterExpressionElement) Validate() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Validate")
	ret0, _ := ret[0].(error)
	return ret0
}

// Validate indicates an expected call of Validate.
func (mr *MockTagFilterExpressionElementMockRecorder) Validate() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Validate", reflect.TypeOf((*MockTagFilterExpressionElement)(nil).Validate))
}
