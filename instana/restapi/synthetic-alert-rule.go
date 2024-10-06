package restapi

// SyntheticAlertRule is the representation of an synthetic alert rule in Instana
type SyntheticAlertRule struct {
	AlertType   string      `json:"alertType"`
	MetricName  string      `json:"metricName"`
	Aggregation Aggregation `json:"aggregation"`
}
