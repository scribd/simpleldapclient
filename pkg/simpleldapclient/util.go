package ldapclient

import "time"

// DaysSinceEpoch returns the number of days since the Unix epoch.
func DaysSinceEpoch() int64 {
	now := time.Now()
	secs := now.Unix()
	mins := secs / 60
	hours := mins / 60
	days := hours / 24

	return days
}

// StringInSlice returns true if the given string is in the given slice
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
