package instana

import (
	"context"

	"github.com/gessnerfl/terraform-provider-instana/instana/restapi"
	"github.com/gessnerfl/terraform-provider-instana/instana/tagfilter"
	"github.com/gessnerfl/terraform-provider-instana/tfutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// ResourceInstanaSyntheticAlertConfig the name of the terraform-provider-instana resource to manage Synthetic alert configs
const ResourceInstanaSyntheticAlertConfig = "instana_synthetic_alert_config"

const (
	//SyntheticAlertConfigFieldAlertChannelIDs constant value for the alert channel ids
	SyntheticAlertConfigFieldAlertChannelIDs = "alert_channel_ids"

	//SyntheticAlertConfigFieldCustomPayloadFields
	SyntheticAlertConfigFieldCustomPayloadFields = "custom_payload_fields"

	//SyntheticAlertConfigFieldDescription
	SyntheticAlertConfigFieldDescription = "description"

	//SyntheticAlertConfigFieldName
	SyntheticAlertConfigFieldName = "name"

	//SyntheticAlertConfigFieldRule
	SyntheticAlertConfigFieldRule = "rule"

	//SyntheticAlertConfigFieldSeverity
	SyntheticAlertConfigFieldSeverity = "severity"

	//SyntheticAlertConfigFieldSyntheticTestIds
	SyntheticAlertConfigFieldSyntheticTestIds = "synthetic_test_ids"

	//SyntheticAlertConfigFieldTagFilterExpression
	SyntheticAlertConfigFieldTagFilter = "tag_filter"

	//SyntheticAlertConfigFieldTimeThreshold
	SyntheticAlertConfigFieldTimeThreshold = "time_threshold"

	//SyntheticAlertConfigFieldRuleMetricName constant value for field rule.*.metric_name of resource instana_synthetic_alert_config
	SyntheticAlertConfigFieldRuleMetricName = "metric_name"

	//SyntheticAlertConfigFieldRuleAggregation constant value for field rule.*.aggregation of resource instana_synthetic_alert_config
	SyntheticAlertConfigFieldRuleAggregation = "aggregation"

	SyntheticAlertConfigFieldTimeThresholdViolationsInSequence = "violations_in_sequence"

	SyntheticAlertConfigFieldTimeThresholdViolationsInSequenceViolationsCount = "violations_count"

	SyntheticAlertConfigFieldRuleFailure = "failure"
)

var (
	syntheticAlertRuleTypeKeys = []string{
		"rule.0.failure",
	}

	syntheticAlertSchemaRuleMetricName = &schema.Schema{
		Type:        schema.TypeString,
		Required:    true,
		Description: "The metric name of the synthetic alert rule",
	}

	syntheticAlertSchemaRequiredRuleAggregation = &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		ValidateFunc: validation.StringInSlice(restapi.SupportedAggregations.ToStringSlice(), false),
		Description:  "The aggregation function of the synthetic alert rule",
	}

	syntheticAlertSchemaOptionalRuleAggregation = &schema.Schema{
		Type:         schema.TypeString,
		Optional:     true,
		ValidateFunc: validation.StringInSlice(restapi.SupportedAggregations.ToStringSlice(), false),
		Description:  "The aggregation function of the synthetic alert rule",
	}

	syntheticAlertTimeThresholdTypeKeys = []string{
		"time_threshold.0.violations_in_sequence",
	}
)

var (
	syntheticAlertConfigSchemaAlertChannelIDs = &schema.Schema{
		Type:     schema.TypeSet,
		MinItems: 0,
		MaxItems: 1024,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Optional:    true,
		Description: "List of IDs of alert channels defined in Instana",
	}

	syntheticAlertConfigSchemaDescription = &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		Description:  "Description of the synthetic alert configuration",
		ValidateFunc: validation.StringLenBetween(0, 65536),
	}

	syntheticAlertConfigSchemaName = &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		Description:  "Name of the synthetic alert configuration",
		ValidateFunc: validation.StringLenBetween(0, 256),
	}

	syntheticAlertConfigSchemaRule = &schema.Schema{
		Type:        schema.TypeList,
		MinItems:    1,
		MaxItems:    1,
		Required:    true,
		Description: "Indicates the type of rule this alert configuration is about",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				SyntheticAlertConfigFieldRuleFailure: {
					Type:        schema.TypeList,
					MinItems:    0,
					MaxItems:    1,
					Optional:    true,
					Description: "Rule based on the failure of the configured alert configuration target",
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							SyntheticAlertConfigFieldRuleMetricName:  syntheticAlertSchemaRuleMetricName,
							SyntheticAlertConfigFieldRuleAggregation: syntheticAlertSchemaOptionalRuleAggregation,
						},
					},
					ExactlyOneOf: syntheticAlertRuleTypeKeys,
				},
			},
		},
	}

	syntheticAlertConfigSchemaSeverity = &schema.Schema{
		Type:         schema.TypeInt,
		Optional:     true,
		ValidateFunc: validation.IntBetween(5, 10),
		Description:  "The severity of the alert when triggered",
	}

	syntheticAlertConfigSyntheticTestIds = &schema.Schema{
		Type: schema.TypeSet,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Required:    true,
		Description: "IDs of the synthetic tests that this Smart Alert configuration is applied to",
	}

	syntheticAlertConfigSchemaTagFilter = RequiredTagFilterExpressionSchema

	syntheticAlertConfigSchemaTimeThreshold = &schema.Schema{
		Type:        schema.TypeList,
		MinItems:    1,
		MaxItems:    1,
		Required:    true,
		Description: "Indicates the type of violation of the defined threshold.",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				SyntheticAlertConfigFieldTimeThresholdViolationsInSequence: {
					Type:        schema.TypeList,
					MinItems:    0,
					MaxItems:    1,
					Optional:    true,
					Description: "Time threshold base on violations in period",
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							SyntheticAlertConfigFieldTimeThresholdViolationsInSequenceViolationsCount: {
								Type:         schema.TypeInt,
								Optional:     true,
								ValidateFunc: validation.IntBetween(1, 12),
								Description:  "The violations appeared in the period",
							},
						},
					},
					ExactlyOneOf: syntheticAlertTimeThresholdTypeKeys,
				},
			},
		},
	}
)

var syntheticAlertConfigResourceSchema = map[string]*schema.Schema{
	SyntheticAlertConfigFieldAlertChannelIDs:     syntheticAlertConfigSchemaAlertChannelIDs,
	SyntheticAlertConfigFieldCustomPayloadFields: buildCustomPayloadFields(),
	SyntheticAlertConfigFieldDescription:         syntheticAlertConfigSchemaDescription,
	SyntheticAlertConfigFieldName:                syntheticAlertConfigSchemaName,
	SyntheticAlertConfigFieldRule:                syntheticAlertConfigSchemaRule,
	SyntheticAlertConfigFieldSeverity:            syntheticAlertConfigSchemaSeverity,
	SyntheticAlertConfigFieldSyntheticTestIds:    syntheticAlertConfigSyntheticTestIds,
	SyntheticAlertConfigFieldTagFilter:           syntheticAlertConfigSchemaTagFilter,
	SyntheticAlertConfigFieldTimeThreshold:       syntheticAlertConfigSchemaTimeThreshold,
}

// NewSyntheticAlertConfigResourceHandle creates a new instance of the ResourceHandle for synthetic alert configs
func NewSyntheticAlertConfigResourceHandle() ResourceHandle[*restapi.SyntheticAlertConfig] {
	return &syntheticAlertConfigResource{
		metaData: ResourceMetaData{
			ResourceName:  ResourceInstanaSyntheticAlertConfig,
			Schema:        syntheticAlertConfigResourceSchema,
			SchemaVersion: 1,
		},
		resourceProvider: func(api restapi.InstanaAPI) restapi.RestResource[*restapi.SyntheticAlertConfig] {
			return api.SyntheticAlertConfigs()
		},
	}
}

type syntheticAlertConfigResource struct {
	metaData         ResourceMetaData
	resourceProvider func(api restapi.InstanaAPI) restapi.RestResource[*restapi.SyntheticAlertConfig]
}

func (r *syntheticAlertConfigResource) MetaData() *ResourceMetaData {
	return &r.metaData
}

func (r *syntheticAlertConfigResource) StateUpgraders() []schema.StateUpgrader {
	return []schema.StateUpgrader{
		{
			Type:    r.schemaV0().CoreConfigSchema().ImpliedType(),
			Upgrade: r.stateUpgradeV0,
			Version: 0,
		},
	}
}

func (r *syntheticAlertConfigResource) GetRestResource(api restapi.InstanaAPI) restapi.RestResource[*restapi.SyntheticAlertConfig] {
	return r.resourceProvider(api)
}

func (r *syntheticAlertConfigResource) SetComputedFields(_ *schema.ResourceData) error {
	return nil
}

func (r *syntheticAlertConfigResource) UpdateState(d *schema.ResourceData, config *restapi.SyntheticAlertConfig) error {
	severity, err := ConvertSeverityFromInstanaAPIToTerraformRepresentation(config.Severity)
	if err != nil {
		return err
	}

	var normalizedTagFilterString *string
	if config.TagFilterExpression != nil {
		normalizedTagFilterString, err = tagfilter.MapTagFilterToNormalizedString(config.TagFilterExpression)
		if err != nil {
			return err
		}
	}

	d.SetId(config.ID)
	return tfutils.UpdateState(d, map[string]interface{}{
		SyntheticAlertConfigFieldAlertChannelIDs:  config.AlertChannelIDs,
		DefaultCustomPayloadFieldsName:            mapCustomPayloadFieldsToSchema(config),
		SyntheticAlertConfigFieldDescription:      config.Description,
		SyntheticAlertConfigFieldName:             config.Name,
		SyntheticAlertConfigFieldRule:             r.mapRuleToSchema(config),
		SyntheticAlertConfigFieldSeverity:         severity,
		SyntheticAlertConfigFieldSyntheticTestIds: config.SyntheticTestIds,
		SyntheticAlertConfigFieldTimeThreshold:    r.mapTimeThresholdToSchema(config),
		SyntheticAlertConfigFieldTagFilter:        normalizedTagFilterString,
	})
}

func (r *syntheticAlertConfigResource) mapRuleToSchema(config *restapi.SyntheticAlertConfig) []map[string]interface{} {
	ruleAttribute := make(map[string]interface{})
	ruleAttribute[SyntheticAlertConfigFieldRuleMetricName] = config.Rule.MetricName
	ruleAttribute[SyntheticAlertConfigFieldRuleAggregation] = config.Rule.Aggregation

	alertType := r.mapAlertTypeToSchema(config.Rule.AlertType)
	rule := make(map[string]interface{})
	rule[alertType] = []interface{}{ruleAttribute}
	result := make([]map[string]interface{}, 1)
	result[0] = rule
	return result
}

func (r *syntheticAlertConfigResource) mapAlertTypeToSchema(alertType string) string {
	if alertType == "failure" {
		return SyntheticAlertConfigFieldRuleFailure
	}
	return alertType
}

func (r *syntheticAlertConfigResource) mapTimeThresholdToSchema(config *restapi.SyntheticAlertConfig) []map[string]interface{} {
	timeThresholdConfig := make(map[string]interface{})
	if config.TimeThreshold.ViolationsCount != nil {
		timeThresholdConfig[SyntheticAlertConfigFieldTimeThresholdViolationsInSequenceViolationsCount] = int(*config.TimeThreshold.ViolationsCount)
	}

	timeThresholdType := r.mapTimeThresholdTypeToSchema(config.TimeThreshold.Type)
	timeThreshold := make(map[string]interface{})
	timeThreshold[timeThresholdType] = []interface{}{timeThresholdConfig}
	result := make([]map[string]interface{}, 1)
	result[0] = timeThreshold
	return result
}

func (r *syntheticAlertConfigResource) mapTimeThresholdTypeToSchema(input string) string {
	if input == "violationsInSequence" {
		return SyntheticAlertConfigFieldTimeThresholdViolationsInSequence
	}
	return input
}

func (r *syntheticAlertConfigResource) MapStateToDataObject(d *schema.ResourceData) (*restapi.SyntheticAlertConfig, error) {
	severity, err := ConvertSeverityFromTerraformToInstanaAPIRepresentation(d.Get(SyntheticAlertConfigFieldSeverity).(string))
	if err != nil {
		return nil, err
	}

	var tagFilter *restapi.TagFilter
	tagFilterStr, ok := d.GetOk(SyntheticAlertConfigFieldTagFilter)
	if ok {
		tagFilter, err = r.mapTagFilterExpressionFromSchema(tagFilterStr.(string))
		if err != nil {
			return &restapi.SyntheticAlertConfig{}, err
		}
	}

	customPayloadFields, err := mapDefaultCustomPayloadFieldsFromSchema(d)
	if err != nil {
		return &restapi.SyntheticAlertConfig{}, err
	}

	return &restapi.SyntheticAlertConfig{
		ID:                    d.Id(),
		AlertChannelIDs:       ReadStringSetParameterFromResource(d, SyntheticAlertConfigFieldAlertChannelIDs),
		CustomerPayloadFields: customPayloadFields,
		Description:           d.Get(SyntheticAlertConfigFieldDescription).(string),
		Name:                  d.Get(SyntheticAlertConfigFieldName).(string),
		Rule:                  r.mapRuleFromSchema(d),
		Severity:              severity,
		SyntheticTestIds:      d.Get(SyntheticAlertConfigFieldSyntheticTestIds).([]string),
		TagFilterExpression:   tagFilter,
		TimeThreshold:         r.mapTimeThresholdFromSchema(d),
	}, nil
}

func (r *syntheticAlertConfigResource) mapRuleFromSchema(d *schema.ResourceData) restapi.SyntheticAlertRule {
	ruleSlice := d.Get(SyntheticAlertConfigFieldRule).([]interface{})
	rule := ruleSlice[0].(map[string]interface{})
	for alertType, v := range rule {
		configSlice := v.([]interface{})
		if len(configSlice) == 1 {
			config := configSlice[0].(map[string]interface{})
			return r.mapRuleConfigFromSchema(config, alertType)
		}
	}
	return restapi.SyntheticAlertRule{}
}

func (r *syntheticAlertConfigResource) mapRuleConfigFromSchema(config map[string]interface{}, alertType string) restapi.SyntheticAlertRule {
	return restapi.SyntheticAlertRule{
		AlertType:   r.mapAlertTypeFromSchema(alertType),
		MetricName:  config[SyntheticAlertConfigFieldRuleMetricName].(string),
		Aggregation: restapi.Aggregation(config[SyntheticAlertConfigFieldRuleAggregation].(string)),
	}
}

func (r *syntheticAlertConfigResource) mapAlertTypeFromSchema(alertType string) string {
	if alertType == SyntheticAlertConfigFieldRuleFailure {
		return "failure"
	}
	return alertType
}

func (r *syntheticAlertConfigResource) mapTagFilterExpressionFromSchema(input string) (*restapi.TagFilter, error) {
	parser := tagfilter.NewParser()
	expr, err := parser.Parse(input)
	if err != nil {
		return nil, err
	}

	mapper := tagfilter.NewMapper()
	return mapper.ToAPIModel(expr), nil
}

func (r *syntheticAlertConfigResource) mapTimeThresholdFromSchema(d *schema.ResourceData) restapi.SyntheticTimeThreshold {
	timeThresholdSlice := d.Get(SyntheticAlertConfigFieldTimeThreshold).([]interface{})
	timeThreshold := timeThresholdSlice[0].(map[string]interface{})
	for timeThresholdType, v := range timeThreshold {
		configSlice := v.([]interface{})
		if len(configSlice) == 1 {
			config := configSlice[0].(map[string]interface{})
			var violationsPtr *int32
			if v, ok := config[SyntheticAlertConfigFieldTimeThresholdViolationsInSequence]; ok {
				violations := int32(v.(int))
				violationsPtr = &violations
			}
			return restapi.SyntheticTimeThreshold{
				Type:            r.mapTimeThresholdTypeFromSchema(timeThresholdType),
				ViolationsCount: violationsPtr,
			}
		}
	}
	return restapi.SyntheticTimeThreshold{}
}

func (r *syntheticAlertConfigResource) mapTimeThresholdTypeFromSchema(input string) string {
	if input == SyntheticAlertConfigFieldTimeThresholdViolationsInSequence {
		return "violationsInSequence"
	}
	return input
}

func (r *syntheticAlertConfigResource) stateUpgradeV0(_ context.Context, state map[string]interface{}, _ interface{}) (map[string]interface{}, error) {
	if _, ok := state[SyntheticAlertConfigFieldName]; ok {
		state[SyntheticAlertConfigFieldName] = state[SyntheticAlertConfigFieldName]
		delete(state, SyntheticAlertConfigFieldName)
	}
	return state, nil
}

func (r *syntheticAlertConfigResource) schemaV0() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			SyntheticAlertConfigFieldAlertChannelIDs:  syntheticAlertConfigSchemaAlertChannelIDs,
			DefaultCustomPayloadFieldsName:            buildCustomPayloadFields(),
			SyntheticAlertConfigFieldDescription:      syntheticAlertConfigSchemaDescription,
			SyntheticAlertConfigFieldName:             syntheticAlertConfigSchemaName,
			SyntheticAlertConfigFieldRule:             syntheticAlertConfigSchemaRule,
			SyntheticAlertConfigFieldSeverity:         syntheticAlertConfigSchemaSeverity,
			SyntheticAlertConfigFieldSyntheticTestIds: syntheticAlertConfigSyntheticTestIds,
			SyntheticAlertConfigFieldTimeThreshold:    syntheticAlertConfigSchemaTimeThreshold,
			SyntheticAlertConfigFieldTagFilter:        syntheticAlertConfigSchemaTagFilter,
		},
	}
}
