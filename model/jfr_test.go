package model

import (
	"context"
	"github.com/elastic/apm-server/transform"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	profile, err := os.Open("../testdata/profile/profile.jfr")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		if err := profile.Close(); err != nil {
			t.Error(err)
		}
	}()

	jfrProfile, err := ParseJfrProfile(profile)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, int64(1613997069036000000), jfrProfile.startNanos)
	assert.Equal(t, 2, len(jfrProfile.samples))
	assert.Equal(t, 2, len(jfrProfile.stackTraces))

	event := JfrProfileEvent{
		Metadata: Metadata{Service: Service{Name: "myService", Environment: "test"}},
		Profile:  jfrProfile,
	}
	events := event.Transform(context.Background(), &transform.Config{DataStreams: true})
	assert.Equal(t, 2, len(events))
}
