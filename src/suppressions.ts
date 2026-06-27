// Detect inline suppression comments in source content.
//
// Supported comment styles:
//   // demo-killer-disable DK-SEC-001
//   #  demo-killer-disable DK-SEC-001
//   (asterisk) demo-killer-disable DK-SEC-001 (asterisk-slash)
//
// The pattern matches any of the above and extracts the space-separated rule IDs.
// Returns true if the given ruleId is suppressed anywhere in the content.

function extractRuleIds(text: string): string[] {
  // Find all DK-XXX tokens in the text
  const matches = text.match(/DK-[\w-]+/g);
  return matches ?? [];
}

export function findSuppressionComments(content: string, ruleId: string): boolean {
  // Split into lines and check each for a suppression directive
  const lines = content.split(/\r?\n/);

  for (const line of lines) {
    // Match lines that contain the directive keyword after a comment opener
    const directiveMatch = line.match(
      /(?:\/\/|#)\s*demo-killer-disable\s+(.+)$/,
    );
    if (directiveMatch) {
      const ids = extractRuleIds(directiveMatch[1]);
      if (ids.includes(ruleId)) {
        return true;
      }
    }

    // Match block-comment style: (asterisk) demo-killer-disable ... (asterisk-slash)
    // We look for "demo-killer-disable" surrounded by block comment markers
    const blockMatch = line.match(
      /demo-killer-disable\s+((?:(?!demo-killer)[\s\S])*)(?:\*\/|$)/,
    );
    if (blockMatch) {
      const ids = extractRuleIds(blockMatch[1]);
      if (ids.includes(ruleId)) {
        return true;
      }
    }
  }

  return false;
}
