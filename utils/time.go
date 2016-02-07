package utils

import (
	"fmt"
	"time"
)

const day = 24 * time.Hour

func FormatDuration(duration time.Duration) string {
	if duration < 0 {
		return "-" + FormatDuration(-duration)
	}

	days := duration / day
	duration = duration % day

	if days > 0 {
		return fmt.Sprintf("%dd%s", days, duration)
	} else {
		return fmt.Sprintf("%s", duration)
	}
}
