package output

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
)

type statWriter interface {
	Stat() (os.FileInfo, error)
}

func SupportsColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := w.(statWriter)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func Rainbow(text string, freq, seed float64) string {
	if !SupportsColor(os.Stdout) {
		return text
	}
	var result strings.Builder
	index := 0
	for _, char := range text {
		if char == '\n' || char == '\r' || char == ' ' || char == '\t' {
			result.WriteRune(char)
			continue
		}
		red := int(math.Sin(freq*float64(index)+seed)*127 + 128)
		green := int(math.Sin(freq*float64(index)+seed+2*math.Pi/3)*127 + 128)
		blue := int(math.Sin(freq*float64(index)+seed+4*math.Pi/3)*127 + 128)
		result.WriteString(fmt.Sprintf("\033[38;2;%d;%d;%dm%c", red, green, blue, char))
		index++
	}
	result.WriteString(ansiReset)
	return result.String()
}

func paint(color, text string) string {
	if color == "" {
		return text
	}
	return color + text + ansiReset
}
