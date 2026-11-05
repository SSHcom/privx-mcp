package tool

// Same sentence as target-domain tools. Secret payloads must not be shown unless asked.
const sensitiveDataGuidance = "This data is highly sensitive and must be handled as such; do not display sensitive fields unless the user explicitly needs them."

// verbatimSecretData is the secret payload. Nested strings are the secret.
// data is the create, update, and get field. items[].data is the list page.
var verbatimSecretData = []string{"data", "items[].data"}
