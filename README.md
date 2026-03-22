# NPM Security Scanner

A bash-based tool that scans all npm projects in a directory tree for recently published packages, helping detect potential supply chain attacks and suspicious package updates.

## Why This Matters

Supply chain attacks targeting npm packages are a real threat. Malicious actors often:
- Compromise legitimate packages and push malicious updates
- Create typosquatting packages that get installed by mistake
- Publish malicious packages hoping developers will use them

This scanner helps identify recently published packages in installed npm packages based on a configurable age threshold value in hours.

## Features

- **Recursive scanning** - Finds all npm projects in a directory tree
- **Direct vs nested dependency tracking** - Shows if packages are direct dependencies or transitive
- **Performance optimized** - Caches npm registry queries across projects (YMMV in terms of performance gains)
- **Security-focused** - Validates inputs, prevents path traversal attacks
- **Flexible output** - Human-readable summary, CSV, JSONL, JSON array, or structured JSON with metadata
- **Debug support** - Multiple debug levels for troubleshooting

## Requirements

- **Linux** (uses GNU `date` command)
- **Bash 4.0+** (for associative arrays)
- **jq** - JSON processor
- **npm** - Node package manager
- **Standard utilities**: `date`, `find`, `basename`, `dirname`

## Installation

1. Clone the repository:
```bash
git clone https://github.com/nyxx88/scan-npm-packages.git
cd scan-npm-packages
```

2. Make the script executable:
```bash
chmod +x bash-scan-npm-projects.sh
```

3. Verify dependencies are installed:
```bash
# Check bash version
bash --version

# Install jq if needed (Ubuntu/Debian)
sudo apt-get install jq

# Install jq if needed (CentOS/RHEL)
sudo yum install jq
```

## Usage

### Basic Usage

```bash
# Scan current directory with 24-hour threshold (CSV output)
./bash-scan-npm-projects.sh

# Scan specific directory
./bash-scan-npm-projects.sh ~/projects

# Custom time threshold (in hours)
./bash-scan-npm-projects.sh ~/projects 48

# Specify output format (CSV or JSON variants)
./bash-scan-npm-projects.sh -o jsonl ~/projects 24
./bash-scan-npm-projects.sh -o json-array ~/projects 24
./bash-scan-npm-projects.sh -o json-structured ~/projects 24
```

### Risk Appetite Guidelines

Choose a threshold based on your security posture:

| Hours | Risk Level | Use Case |
|-------|-----------|----------|
| 6     | Extreme paranoia | CI/CD pipelines, production deployments |
| 24    | Balanced approach | **Recommended default** |
| 48    | Moderate risk | Development environments |
| 168   | One week | Stable/legacy environments |

### Output Modes

The scanner supports multiple output formats for different use cases.

#### Human-readable Summary (HEADLESS=false)

Best for manual review and understanding project health.

```bash
HEADLESS=false ./bash-scan-npm-projects.sh ~/projects 24
```

Output:
```
================================================================
                      SCAN SUMMARY
================================================================

Projects Scanned:

  1. my-app
     Path: /Users/user/projects/my-app
     Total packages: 247
     Flagged packages:
       - express@4.18.2
       - lodash@4.17.21

Final Summary:
----------------------------------------------------------------
  Projects scanned:         3
  Projects with issues:     1
  Total packages flagged:   2
  Age threshold:            24 hours
```

#### CSV Format (default when HEADLESS=true)

Best for spreadsheet analysis and simple automation.

```bash
./bash-scan-npm-projects.sh ~/projects 24 > results.csv
# or explicitly:
./bash-scan-npm-projects.sh -o csv ~/projects 24 > results.csv
```

Output:
```csv
/path/to/package-lock.json,my-app,express@4.18.2,[DIRECT],2026-03-21T10:30:00Z,18
/path/to/package-lock.json,my-app,lodash@4.17.21,[nested],2026-03-20T14:15:00Z,32
```

Columns: `lockfile_path,project_name,package@version,type,publish_date,age_hours`

#### JSONL Format (JSON Lines)

Best for streaming processing and line-by-line parsing.

```bash
./bash-scan-npm-projects.sh -o jsonl ~/projects 24 > results.jsonl
```

Output (one JSON object per line):
```json
{"lockfile":"/path/to/package-lock.json","project":"my-app","package":"express@4.18.2","type":"[DIRECT]","published":"2026-03-21T10:30:00Z","age_hours":18}
{"lockfile":"/path/to/package-lock.json","project":"my-app","package":"lodash@4.17.21","type":"[nested]","published":"2026-03-20T14:15:00Z","age_hours":32}
```

#### JSON Array Format

Best for processing entire result set as a single JSON array.

```bash
./bash-scan-npm-projects.sh -o json-array ~/projects 24 > results.json
```

Output:
```json
[
  {
    "lockfile": "/path/to/package-lock.json",
    "project": "my-app",
    "package": "express@4.18.2",
    "type": "[DIRECT]",
    "published": "2026-03-21T10:30:00Z",
    "age_hours": 18
  },
  {
    "lockfile": "/path/to/package-lock.json",
    "project": "my-app",
    "package": "lodash@4.17.21",
    "type": "[nested]",
    "published": "2026-03-20T14:15:00Z",
    "age_hours": 32
  }
]
```

#### Structured JSON Format

Best for comprehensive analysis with metadata and statistics.

```bash
./bash-scan-npm-projects.sh -o json-structured ~/projects 24 > results.json
```

Output:
```json
{
  "scan_metadata": {
    "scan_timestamp": 1711095845,
    "threshold_hours": 24,
    "search_directory": "/home/user/projects"
  },
  "summary": {
    "total_projects": 3,
    "projects_with_issues": 1,
    "total_packages_flagged": 2
  },
  "performance": {
    "cache_hits": 45,
    "cache_misses": 203,
    "cache_hit_rate_percent": 18
  },
  "projects": [
    {
      "name": "my-app",
      "path": "/home/user/projects/my-app",
      "total_packages": 247,
      "flagged_count": 2,
      "flagged_packages": [
        {
          "package": "express@4.18.2",
          "type": "[DIRECT]",
          "published": "2026-03-21T10:30:00Z",
          "age_hours": 18
        },
        {
          "package": "lodash@4.17.21",
          "type": "[nested]",
          "published": "2026-03-20T14:15:00Z",
          "age_hours": 32
        }
      ]
    }
  ]
}
```

### Debug Mode

Enable debug output to troubleshoot issues:

```bash
# Basic debug info (level 1)
DEBUG=1 ./bash-scan-npm-projects.sh ~/projects 24 2>debug.log

# Verbose debug (level 2)
DEBUG=2 ./bash-scan-npm-projects.sh ~/projects 24 2>debug.log

# Very verbose (level 3)
DEBUG=3 ./bash-scan-npm-projects.sh ~/projects 24 2>debug.log
```

## Understanding the Output

### Dependency Types

- **[DIRECT]** - Packages you explicitly added to `package.json`
  - You have direct control over these
  - Easier to update or replace

- **[nested]** - Transitive dependencies (dependencies of your dependencies)
  - Indirect control - must wait for parent package to update
  - Still pose security risks!

### CSV Columns

```
lockfile_path,project_name,package@version,type,publish_date,age_hours
```

Example:
```csv
/app/package-lock.json,my-app,axios@1.6.7,[DIRECT],2026-03-22T08:45:00Z,6
```

### JSON Fields

All JSON formats include these fields for each flagged package:

- **lockfile**: Absolute path to package-lock.json
- **project**: Project name (from package-lock.json or directory name)
- **package**: Package name and version (e.g., "express@4.18.2")
- **type**: "[DIRECT]" or "[nested]" dependency
- **published**: ISO 8601 timestamp when package version was published
- **age_hours**: Hours since publication

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HEADLESS` | `true` | Set to `false` for human-readable output |
| `OUTPUT_FORMAT` | `csv` | Output format when HEADLESS=true: `csv`, `jsonl`, `json-array`, or `json-structured` (can also use `-o` flag) |
| `DEBUG` | `0` | Debug level: `0` (off), `1` (basic), `2` (verbose), `3` (very verbose) |

## Examples

### Example 1: Daily Security Scan in CI/CD

```bash
#!/bin/bash
# Run in CI pipeline to check for suspicious packages

# CSV output for simple parsing
./bash-scan-npm-projects.sh -o csv /workspace 24 > scan-results.csv

if [ -s scan-results.csv ]; then
  echo "WARNING: Recently published packages detected!"
  cat scan-results.csv
  exit 1
fi
```

### Example 2: Structured JSON for Monitoring Dashboard

```bash
#!/bin/bash
# Generate structured JSON for dashboard integration

./bash-scan-npm-projects.sh -o json-structured ~/projects 24 > scan-results.json

# POST to monitoring API
curl -X POST https://monitoring.company.com/api/npm-scan \
  -H "Content-Type: application/json" \
  -d @scan-results.json
```

### Example 3: JSONL for Stream Processing

```bash
#!/bin/bash
# Process each flagged package individually

./bash-scan-npm-projects.sh -o jsonl ~/projects 24 | while read -r line; do
  # Each line is a complete JSON object
  package=$(echo "$line" | jq -r '.package')
  age=$(echo "$line" | jq -r '.age_hours')

  if [ "$age" -lt 12 ]; then
    echo "CRITICAL: $package published in last 12 hours!"
  fi
done
```

### Example 4: Weekly Audit with Email Report

```bash
#!/bin/bash
# Cron job: 0 9 * * 1 (Every Monday at 9 AM)

HEADLESS=false ./bash-scan-npm-projects.sh ~/projects 168 > weekly-report.txt

if grep -q "WARN:" weekly-report.txt; then
  mail -s "NPM Security Scan - Issues Found" security@company.com < weekly-report.txt
fi
```

### Example 5: Pre-deployment Check

```bash
#!/bin/bash
# Check before deploying to production

echo "Running security scan before deployment..."
HEADLESS=false ./bash-scan-npm-projects.sh . 6

read -p "Proceed with deployment? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Deployment cancelled"
  exit 1
fi
```

## Performance Notes

- **Main bottleneck**: npm registry queries (~790ms per package)
- **Optimization**: In-memory cache reduces redundant queries across projects
- **Typical scan time**: ~30-60 seconds for a project with 200 packages

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Configuration error (invalid parameters) |
| 2 | Missing dependency (required tool not found) |
| 3 | Runtime error (file operations, command failures) |

## Security Considerations

### What This Tool Does

- Detects recently published packages
- Identifies direct vs transitive dependencies
- Validates package names and paths
- Prevents path traversal attacks

### What This Tool Does NOT Do

- Does not guarantee packages are safe (just flags recent ones)
- Does not analyze package code for malware
- Does not replace `npm audit` (complementary tool)

### Recommended Actions When Packages Are Flagged

1. **Research the package maintainer**
   - Check their GitHub profile and history
   - Look for verified badges or organizational backing

2. **Review recent changes**
   - Read the changelog and release notes
   - Check GitHub commits for suspicious code

3. **Check community feedback**
   - Look for issues or discussions about the release
   - Search Twitter/Reddit for mentions

4. **Verify on npm registry**
   - Check download statistics
   - Review package dependencies

5. **Consider alternatives**
   - Pin to previous version temporarily
   - Look for alternative packages
   - Wait a few days for community vetting

6. **Run complementary scans**
   ```bash
   npm audit
   npm audit fix
   ```
