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
const ResourceInstanaSyntheticAlertConfig = "instana_Synthetic_alert_config"

const (
	//SyntheticAlertConfigFieldAlertChannelIds constant value for the alert channel ids
	SyntheticAlertConfigFieldAlertChannelIds = "alert_channel_ids"

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
	SyntheticAlertConfigFieldTagFilterExpression = "tag_filter_expression"

	//SyntheticAlertConfigFieldTimeThreshold
	SyntheticAlertConfigFieldTimeThreshold = "time_threshold"

	//SyntheticAlertConfigFieldRuleMetricName constant value for field rule.*.metric_name of resource instana_synthetic_alert_config
	SyntheticAlertConfigFieldRuleMetricName = "metric_name"

	//SyntheticAlertConfigFieldRuleAggregation constant value for field rule.*.aggregation of resource instana_synthetic_alert_config
	SyntheticAlertConfigFieldRuleAggregation = "aggregation"
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

	syntheticAlertSchemaDescription = &schema.Schema{
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
				}
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
		Type:     schema.TypeSet,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Required:    true,
		Description: "IDs of the synthetic tests that this Smart Alert configuration is applied to",
	}

	syntheticAlertConfigSchemaTagFilterExpression = RequiredTagFilterExpressionSchema

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
					Description: "Time threshold base on violations in sequence",
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							SyntheticAlertConfigFieldTimeThresholdViolationsInSequenceViolations: {
								Type:         schema.TypeInt,
								Optional:     true,
								ValidateFunc: validation.IntBetween(1, 12),
								Description:  "The violations appeared in the sequence",
							},
						},
					},
					ExactlyOneOf: syntheticAlertTimeThresholdTypeKeys,
				}
		},
	}

)var syntheticAlertConfigResourceSchema = map[string]*schema.Schema{
	SyntheticAlertConfigFieldAlertChannelIds:  syntheticAlertConfigSchemaAlertChannelIDs,
	SyntheticAlertConfigFieldCustomPayloadFields: buildCustomPayloadFields(),
	SyntheticAlertConfigFieldDescription: syntheticAlertSchemaDescription,
	SyntheticAlertConfigFieldName: syntheticAlertConfigSchemaName,
	SyntheticAlertConfigFieldRule: syntheticAlertConfigSchemaRule,
	SyntheticAlertConfigFieldSeverity: syntheticAlertConfigSchemaSeverity,
	SyntheticAlertConfigFieldSyntheticTestIds: syntheticAlertConfigSyntheticTestIds,
	SyntheticAlertConfigFieldTagFilterExpression: syntheticAlertConfigSchemaTagFilterExpression,
	SyntheticAlertConfigFieldTimeThreshold: syntheticAlertConfigSchemaTimeThreshold,
}

// NewSyntheticAlertConfigResourceHandle creates a new instance of the ResourceHandle for application alert configs
func NewSyntheticAlertConfigResourceHandle() ResourceHandle[*restapi.SyntheticAlertConfig] {
	return &applicationAlertConfigResource{
		metaData: ResourceMetaData{
			ResourceName:     ResourceInstanaSyntheticAlertConfig,
			Schema:           applicationAlertConfigResourceSchema,
			SkipIDGeneration: true,
			SchemaVersion:    1,
		},
		resourceProvider: func(api restapi.InstanaAPI) restapi.RestResource[*restapi.SyntheticAlertConfig] {
			return api.SyntheticAlertConfigs()
		},
	}
}