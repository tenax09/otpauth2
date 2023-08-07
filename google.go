package otpauth2

import (
	"crypto/md5"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// CreateSecret create new secret
// 16 characters, randomly chosen from the allowed base32 characters.
func CreateSecret(accountSecret string) string {
	w := md5.New()
	w.Write([]byte(accountSecret))
	s := base32.StdEncoding.EncodeToString(w.Sum(nil))
	return strings.Trim(s, "=")
}

// VerifyCode Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
func VerifyCode(secret, code string, discrepancy int64) bool {
	curTimeSlice := time.Now().Unix() / 30
	for i := -discrepancy; i <= discrepancy; i++ {
		calculatedCode := GetCode(secret, curTimeSlice+i)
		if calculatedCode == code {
			return true
		}
	}
	return false
}

// GetCode Calculate the code, with given secret and point in time
func GetCode(secret string, timeSlices ...int64) string {
	var timeSlice int64
	switch len(timeSlices) {
	case 0:
		timeSlice = time.Now().Unix() / 30
	case 1:
		timeSlice = timeSlices[0]
	default:
		return ""
	}
	if len(secret) == 26 {
		secret = secret + "======"
	}
	secret = strings.ToUpper(secret)
	secretKey, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return ""
	}
	tim, err := hex.DecodeString(fmt.Sprintf("%016x", timeSlice))
	if err != nil {
		return ""
	}
	hm := HmacSha1(secretKey, tim)
	offset := hm[len(hm)-1] & 0x0F
	hashpart := hm[offset : offset+4]
	value, err := strconv.ParseInt(hex.EncodeToString(hashpart), 16, 0)
	if err != nil {
		return ""
	}
	value = value & 0x7FFFFFFF
	modulo := int64(math.Pow(10, 6))
	format := fmt.Sprintf("%%0%dd", 6)
	return fmt.Sprintf(format, value%modulo)
}
