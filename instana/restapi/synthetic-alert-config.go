package restapi

// GlobalApplicationAlertConfigsResourcePath the base path of the Instana REST API for global synthetic alert configs
const GlobalSyntheticAlertConfigsResourcePath = EventSettingsBasePath + "/global-alert-configs/synthetics"

// ApplicationAlertConfig is the representation of an application alert configuration in Instana
type SyntheticAlertConfig struct {
	ID                    string                    `json:"id"`
	Name                  string                    `json:"name"`
	Description           string                    `json:"description"`
	Severity              int                       `json:"severity"`
	TagFilterExpression   *TagFilter                `json:"tagFilterExpression"`
	AlertChannelIDs       []string                  `json:"alertChannelIds"`
	CustomerPayloadFields []CustomPayloadField[any] `json:"customPayloadFields"`
	Rule                  SyntheticAlertRule        `json:"rule"`
	TimeThreshold         SyntheticTimeThreshold    `json:"timeThreshold"`
	SyntheticTestIds      []string                  `json:"syntheticTestIds"`
}

// GetIDForResourcePath implementation of the interface InstanaDataObject
func (a *SyntheticAlertConfig) GetIDForResourcePath() string {
	return a.ID
}

// GetCustomerPayloadFields implementation of the interface customPayloadFieldsAwareInstanaDataObject
func (a *SyntheticAlertConfig) GetCustomerPayloadFields() []CustomPayloadField[any] {
	return a.CustomerPayloadFields
}

// SetCustomerPayloadFields implementation of the interface customPayloadFieldsAwareInstanaDataObject
func (a *SyntheticAlertConfig) SetCustomerPayloadFields(fields []CustomPayloadField[any]) {
	a.CustomerPayloadFields = fields
}
