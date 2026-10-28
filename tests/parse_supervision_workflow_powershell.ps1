param([Parameter(Mandatory=$true)][string]$PathToParse)
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($PathToParse, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { exit 2 }
exit 0
