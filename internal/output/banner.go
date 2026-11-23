package output

import "fmt"

// Banner returns a plain banner using the supplied build version.
func Banner(style, version string) string {
	switch style {
	case "short":
		return "╻ ╻┏━┓┏━┓┏━┓\n┃╻┃┣━┫┗━┓┣━┛\n┗┻┛╹ ╹┗━┛╹ v." + version
	case "text":
		return "WASP (Website Audit & Security Profiler) v" + version
	default:
		return fmt.Sprintf("▗▖ ▗▖ ▗▄▖  ▗▄▄▖▗▄▄▖\n▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌ ▐▌\n▐▌█▐▌▐▛▀▜▌ ▝▀▚▖▐▛▀▘\n▐▙█▟▌▐▌ ▐▌▗▄▄▞▘▐▌ v.%s", version)
	}
}
