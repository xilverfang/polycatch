package telegram

import "html"

// escapeHTML prevents Telegram HTML parse issues by escaping dynamic content.
func escapeHTML(value string) string {
	return html.EscapeString(value)
}
