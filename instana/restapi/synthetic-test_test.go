package restapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	syntheticID    = "synthetic-id"
	syntheticLabel = "synthetic-label"
	syntheticUrl   = "https://localhost"
)

func TestInvalidSyntheticBecauseOfMissingID(t *testing.T) {
	synthetic := SyntheticTest{
		Label:     syntheticLabel,
		Locations: []string{""},
		Configuration: SyntheticTestConfig{
			URL:           syntheticUrl,
			SyntheticType: "HTTPAction",
		},
	}

	err := synthetic.Validate()
	assert.Contains(t, err.Error(), "id")
}

func TestInvalidSyntheticBecauseOfMissingLabel(t *testing.T) {
	synthetic := SyntheticTest{
		ID:        syntheticID,
		Locations: []string{""},
		Configuration: SyntheticTestConfig{
			URL:           syntheticUrl,
			SyntheticType: "HTTPAction",
		},
	}

	err := synthetic.Validate()
	assert.Contains(t, err.Error(), "label")
}

func TestInvalidSyntheticBecauseOfMissingLocations(t *testing.T) {
	synthetic := SyntheticTest{
		ID:    syntheticID,
		Label: syntheticLabel,
		Configuration: SyntheticTestConfig{
			URL:           syntheticUrl,
			SyntheticType: "HTTPAction",
		},
	}

	err := synthetic.Validate()
	assert.Contains(t, err.Error(), "locations")
}

func TestInvalidHTTPActionBecauseOfMissingUrl(t *testing.T) {
	synthetic := SyntheticTest{
		ID:        syntheticID,
		Label:     syntheticLabel,
		Locations: []string{""},
		Configuration: SyntheticTestConfig{
			SyntheticType: "HTTPAction",
		},
	}

	err := synthetic.Validate()
	assert.Contains(t, err.Error(), "url")
}

func TestInvalidHTTPScriptBecauseOfMissingScript(t *testing.T) {
	synthetic := SyntheticTest{
		ID:        syntheticID,
		Label:     syntheticLabel,
		Locations: []string{""},
		Configuration: SyntheticTestConfig{
			SyntheticType: "HTTPScript",
		},
	}

	err := synthetic.Validate()
	assert.Contains(t, err.Error(), "script")
}
