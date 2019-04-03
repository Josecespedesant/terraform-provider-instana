// Code generated by MockGen. DO NOT EDIT.
// Source: instana/restapi/rules-api.go

// Package mock_restapi is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	x "github.com/gessnerfl/terraform-provider-instana/instana/restapi"
	gomock "github.com/golang/mock/gomock"
)

// MockRuleResource is a mock of RuleResource interface
type MockRuleResource struct {
	ctrl     *gomock.Controller
	recorder *MockRuleResourceMockRecorder
}

// MockRuleResourceMockRecorder is the mock recorder for MockRuleResource
type MockRuleResourceMockRecorder struct {
	mock *MockRuleResource
}

// NewMockRuleResource creates a new mock instance
func NewMockRuleResource(ctrl *gomock.Controller) *MockRuleResource {
	mock := &MockRuleResource{ctrl: ctrl}
	mock.recorder = &MockRuleResourceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRuleResource) EXPECT() *MockRuleResourceMockRecorder {
	return m.recorder
}

// GetOne mocks base method
func (m *MockRuleResource) GetOne(id string) (x.Rule, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOne", id)
	ret0, _ := ret[0].(x.Rule)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetOne indicates an expected call of GetOne
func (mr *MockRuleResourceMockRecorder) GetOne(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOne", reflect.TypeOf((*MockRuleResource)(nil).GetOne), id)
}

// Upsert mocks base method
func (m *MockRuleResource) Upsert(rule x.Rule) (x.Rule, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Upsert", rule)
	ret0, _ := ret[0].(x.Rule)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Upsert indicates an expected call of Upsert
func (mr *MockRuleResourceMockRecorder) Upsert(rule interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Upsert", reflect.TypeOf((*MockRuleResource)(nil).Upsert), rule)
}

// Delete mocks base method
func (m *MockRuleResource) Delete(rule x.Rule) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", rule)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete
func (mr *MockRuleResourceMockRecorder) Delete(rule interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockRuleResource)(nil).Delete), rule)
}

// DeleteByID mocks base method
func (m *MockRuleResource) DeleteByID(ruleID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByID", ruleID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByID indicates an expected call of DeleteByID
func (mr *MockRuleResourceMockRecorder) DeleteByID(ruleID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByID", reflect.TypeOf((*MockRuleResource)(nil).DeleteByID), ruleID)
}
