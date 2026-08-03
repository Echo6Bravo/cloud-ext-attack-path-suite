#!/usr/bin/env bash
# Mock `claude` CLI for tests/test_orchestrator.sh -- NOT a real tool.
# Behaviour driven by argv/prompt; writes fixture pages into $MOCK_RAW_DIR / $MOCK_SIZES.
#   `mcp list`            -> prints a Tenable-CS connector (+ a decoy) for auto-detection
#   `-p ...SIZING ONLY...`-> writes a 2-account sizes.json
#   `-p ...account='111'` -> writes AWS raw pages;  `...account='8be0927e...'` -> Azure pages
#   `-p ...` (tenant)     -> writes BOTH accounts' pages (a tenant-wide pull returns everything)
set -uo pipefail

if [ "${1:-}" = "mcp" ] && [ "${2:-}" = "list" ]; then
  echo "tenablecs-org1: https://app.tenable.com/api/mcp (HTTP) - connected"
  echo "some-other-server: https://x (HTTP) - connected"
  exit 0
fi

prompt=""
while [ $# -gt 0 ]; do [ "$1" = "-p" ] && prompt="${2:-}"; shift; done

RAW="${MOCK_RAW_DIR:?MOCK_RAW_DIR unset}"
SIZES="${MOCK_SIZES:?MOCK_SIZES unset}"
AZ="8be0927e-f4b3-4528-b3e7-42bb46b029a2"

emit_aws() { # $1 = filename tag
  local t="$1"
  printf '{"resultsList":[{"queryIdToObjectMap":{"q":{"queryId":"q","propertyIdentifierToValueMap":{"EntityName":"aws-host","EntityTypeName":"AwsEc2Instance","EntityTenant":"111111111111","VirtualMachineStatus":"Running","EntityAttributes":[{"typeName":"SeverePermissionActionPrincipalAttribute"}],"OriginatorEntityServiceIdentities":[],"Id":"arn:aws:ec2:us-east-1:111111111111:instance/i-aws1"}}}}]}' > "$RAW/raw_A_${t}_paws.json"
  printf '{"resultsList":[{"queryIdToObjectMap":{"e":{"queryId":"e","propertyIdentifierToValueMap":{"NetworkEndpointHost":"203.0.113.10","NetworkEndpointPort":3389,"NetworkEndpointProtocolType":"TCP","Id":"NetworkEndpoint/arn:aws:ec2:us-east-1:111111111111:instance/i-aws1/203.0.113.10/3389/TCP//"}},"n":{"queryId":"n","propertyIdentifierToValueMap":{"EntityName":"aws-host","Id":"arn:aws:ec2:us-east-1:111111111111:instance/i-aws1"}}}}]}' > "$RAW/raw_B_${t}_paws.json"
  printf '{"resultsList":[{"queryIdToObjectMap":{"s":{"queryId":"s","propertyIdentifierToValueMap":{"PackageVulnerabilityInstanceStatus":"Open","Id":"cve-2025-0001/windows-os/x/Windows/arn:aws:ec2:us-east-1:111111111111:instance/i-aws1"}},"v":{"queryId":"v","propertyIdentifierToValueMap":{"VulnerabilityCvssScore":9.8,"VulnerabilityEpssScore":0.9,"VulnerabilityVprV2MetricsOnCisaKev":true,"VulnerabilitySeverity":"Critical","VulnerabilityProofOfConceptAvailable":true,"Id":"cve-2025-0001"}},"n":{"queryId":"n","propertyIdentifierToValueMap":{"EntityName":"aws-host","EntityTypeName":"AwsEc2Instance","Id":"arn:aws:ec2:us-east-1:111111111111:instance/i-aws1"}}}}]}' > "$RAW/raw_C_${t}_paws.json"
}

emit_azure() { # $1 = filename tag
  local t="$1"
  printf '{"resultsList":[{"queryIdToObjectMap":{"q":{"queryId":"q","propertyIdentifierToValueMap":{"EntityName":"az-host","EntityTypeName":"AzureComputeVirtualMachine","EntityTenant":"%s","VirtualMachineStatus":"Running","EntityAttributes":[],"OriginatorEntityServiceIdentities":[],"Id":"%s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/azh"}}}}]}' "$AZ" "$AZ" > "$RAW/raw_A_${t}_paz.json"
  printf '{"resultsList":[{"queryIdToObjectMap":{"e":{"queryId":"e","propertyIdentifierToValueMap":{"NetworkEndpointHost":"203.0.113.20","NetworkEndpointPort":22,"NetworkEndpointProtocolType":"TCP","Id":"NetworkEndpoint/%s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/azh/203.0.113.20/22/TCP//"}},"n":{"queryId":"n","propertyIdentifierToValueMap":{"EntityName":"az-host","Id":"%s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/azh"}}}}]}' "$AZ" "$AZ" > "$RAW/raw_B_${t}_paz.json"
  printf '{"resultsList":[{"queryIdToObjectMap":{"s":{"queryId":"s","propertyIdentifierToValueMap":{"PackageVulnerabilityInstanceStatus":"Open","Id":"cve-2025-0002/openssh/x/Linux/%s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/azh"}},"v":{"queryId":"v","propertyIdentifierToValueMap":{"VulnerabilityCvssScore":9.1,"VulnerabilityEpssScore":0.8,"VulnerabilityVprV2MetricsOnCisaKev":false,"VulnerabilitySeverity":"High","VulnerabilityProofOfConceptAvailable":true,"Id":"cve-2025-0002"}},"n":{"queryId":"n","propertyIdentifierToValueMap":{"EntityName":"az-host","EntityTypeName":"AzureComputeVirtualMachine","Id":"%s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/azh"}}}}]}' "$AZ" "$AZ" > "$RAW/raw_C_${t}_paz.json"
}

case "$prompt" in
  *"SIZING ONLY"*)
    printf '{"accounts":{"111111111111":40,"%s":30},"regions":{}}' "$AZ" > "$SIZES" ;;
  *"account='111111111111'"*) emit_aws   "111111111111" ;;
  *"account='8be0927e"*)      emit_azure "azure" ;;
  *)                          emit_aws "tenant"; emit_azure "tenant" ;;  # tenant-wide pull = both
esac
exit 0
