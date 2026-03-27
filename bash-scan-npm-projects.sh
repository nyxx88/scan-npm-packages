#!/bin/bash
# ==============================================================================
# Multi-Project NPM Security Scanner (Linux/Bash 4+)
# ==============================================================================
# Purpose: Scan all npm projects in a directory tree for recently published packages
# Platform: Linux with bash 4.0+ (for associative arrays)
# Usage: ./bash-scan-npm-projects.sh [SEARCH_DIR] [HOURS]
#   SEARCH_DIR: Root directory to search (default: current directory)
#   HOURS: Age threshold in hours (default: 24)
# Examples:
#   ./bash-scan-npm-projects.sh                    # Scan current dir, 24h threshold
#   ./bash-scan-npm-projects.sh ~/projects         # Scan ~/projects, 24h threshold
#   ./bash-scan-npm-projects.sh ~/projects 48      # Scan ~/projects, 48h threshold
#   ./bash-scan-npm-projects.sh . 6                # Scan current dir, 6h threshold
#
# Risk appetite samples:
#   6 hours   - Extreme paranoia (CI/CD pipelines, production deployments)
#   24 hours  - Balanced approach (recommended default)
#   48 hours  - Moderate risk tolerance
#   168 hours - One week (for stable environments)
#
# ==============================================================================
# Choosing package-lock.json over package.json:
#
# package-lock.json contains the EXACT versions of all packages installed,
# including transitive dependencies. package.json only lists direct dependencies
# with version ranges (^, ~, etc.), which can resolve to different versions.
#
# For security scanning, we need to know the exact versions installed, not the
# version ranges that could be installed. This is why package-lock.json is more
# reliable as the source of truth for both project names and package versions.
# ==============================================================================

# Enable bash strict mode for better error handling
set -euo pipefail

# ==============================================================================
# Constants and Configuration
# ==============================================================================

# Script metadata
SCRIPT_NAME="$(basename "${0}")"                                                                   # SC2155 fix
readonly SCRIPT_NAME                                                                               # SC2155 fix

# Error codes with semantic meaning
readonly ERR_CONFIG=1        # Configuration errors (invalid parameters)
readonly ERR_DEPENDENCY=2    # Missing tools or dependencies
readonly ERR_RUNTIME=3       # Runtime errors (file operations, command failures)

# Debug levels
readonly DEBUG_LEVEL_1=1     # Basic debug info
readonly DEBUG_LEVEL_2=2     # Verbose debug info
readonly DEBUG_LEVEL_3=3     # Very verbose debug info
DEBUG="${DEBUG:-0}"          # Default to no debug output

# HEADLESS mode
# - true: Outputs formatted results (CSV or JSON) that can be piped to a file
# - false: Outputs a summary of scan results in human readable form
HEADLESS="${HEADLESS:-true}"
readonly HEADLESS

# OUTPUT_FORMAT (only used when HEADLESS=true)
# - csv: CSV formatted output (default for backward compatibility)
# - jsonl: JSON Lines format (one JSON object per line)
# - json-array: Single JSON array of all flagged packages
# - json-structured: Structured JSON with metadata and per-project breakdown
OUTPUT_FORMAT="${OUTPUT_FORMAT:-csv}"
OUTPUT_FORMAT="$(echo "${OUTPUT_FORMAT}" | tr '[:upper:]' '[:lower:]')"  # Convert to lowercase for case-insensitive handling

# Valid output formats (used for validation)
readonly VALID_OUTPUT_FORMATS=("csv" "jsonl" "json-array" "json-structured")

# Time constants
readonly SECONDS_PER_HOUR=3600

# Validation limits
readonly MAX_AGE_THRESHOLD_HOURS=1000000  # ~114 years, prevents integer overflow

# Package scanning constants
readonly NODE_MODULES_PREFIX="node_modules/"
readonly DIRECT_DEPENDENCY=1   # Marker for direct dependencies in associative array

# Required external tools
readonly REQUIRED_TOOLS=("jq" "npm" "date" "find" "basename" "dirname")

# Default values
readonly DEFAULT_DIRECTORY="."
readonly DEFAULT_AGE_THRESHOLD_HOURS=24

# ==============================================================================
# Global State Variables
# ==============================================================================
# These variables are shared between scan_projects() and main()
# They track statistics across all scanned projects

search_dir=""
abs_search_dir=""
age_threshold_hours=0
current_timestamp="$(date "+%s")"
declare -A direct_deps_map    # Associative array mapping package names to dependency status
declare -A npm_cache          # Cache for npm view results: package@version -> publish_date
total_projects=0              # Total number of npm projects found and scanned
total_flagged=0               # Total number of recently published packages found
projects_with_issues=0        # Number of projects containing flagged packages
cache_hits=0                  # Number of cache hits (for performance tracking)
cache_misses=0                # Number of cache misses (for performance tracking)

# Per-project tracking arrays (indexed by project counter)
declare -a project_names=()               # Array of project names
declare -a project_paths=()               # Array of project paths
declare -a project_total_packages=()      # Array of total packages per project
declare -a project_flagged_packages=()    # Array of flagged packages per project (newline-separated strings)

# ==============================================================================
# Utility Functions
# ==============================================================================

# ------------------------------------------------------------------------------
# Display error message and exit with specified code
# Usage: error <exit_code> <message>
# ------------------------------------------------------------------------------
error() {
  local exit_code="${1}"
  local message="${2}"
  echo "Error: ${message}" >&2
  exit "${exit_code}"
}

# ------------------------------------------------------------------------------
# Display debug message if debug level is high enough
# Usage: debug <level> <source> <message>
# ------------------------------------------------------------------------------
debug() {
  local dbg_level="${1}"
  local dbg_source="${2}"
  local dbg_message="${3}"

  if [[ "${DEBUG}" -ge "${dbg_level}" ]]; then
    echo "[DEBUG ${dbg_level}:${dbg_source}] ${dbg_message}" >&2                                   # in case debug() is accidentally called in functions that return values via stdin
  fi
}

# ------------------------------------------------------------------------------
# Display usage information
# ------------------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [-o FORMAT] [SEARCH_DIR] [HOURS]

Arguments:
  -o FORMAT    Output format when HEADLESS=true (default: csv)
               Options: csv, jsonl, json-array, json-structured
  SEARCH_DIR   Root directory to search (default: current directory)
  HOURS        Age threshold in hours (default: 24)
               Packages published within this timeframe will be flagged

Examples:
  ${SCRIPT_NAME}                              # Current dir, 24h, CSV output
  ${SCRIPT_NAME} ~/projects                   # ~/projects, 24h, CSV output
  ${SCRIPT_NAME} -o jsonl ~/projects 48       # ~/projects, 48h, JSONL output
  ${SCRIPT_NAME} -o json-structured . 24      # Current dir, 24h, structured JSON

Environment Variables:
  HEADLESS    Set to "true" (default) for formatted output (CSV/JSON)
              Set to "false" for human-readable summary
              Example: HEADLESS=false ${SCRIPT_NAME} ~/projects 24

  DEBUG       Set debug level (0=off, 1=basic, 2=verbose, 3=very verbose)
              Debug output goes to stderr and can be redirected to a file
              Example: DEBUG=2 ${SCRIPT_NAME} ~/projects 24 2>debug.log

Exit Codes:
  0  Success
  1  Configuration error
  2  Missing dependency
  3  Runtime error
EOF
}

# ------------------------------------------------------------------------------
# Validate bash version meets minimum requirement
# Usage: validate_bash_version
# Note: Script requires bash 4.3+ for namerefs (declare -n) used in validate_value()
#       Also requires bash 4.0+ for associative arrays (declare -A)
#       This script is designed for Linux systems only
# ------------------------------------------------------------------------------
validate_bash_version() {
  local bash_major="${BASH_VERSINFO[0]}"
  local bash_minor="${BASH_VERSINFO[1]}"
  local min_major=4
  local min_minor=3

  # Check if BASH_VERSINFO is available (empty if not running in bash)
  if [[ -z "${bash_major}" ]]; then
    error "${ERR_DEPENDENCY}" "Must run in bash shell (not sh/zsh/dash). Current shell: ${SHELL:-unknown}"
  fi

  # Validate that bash_major is a numeric value
  if ! [[ "${bash_major}" =~ ^[0-9]+$ ]]; then
    error "${ERR_DEPENDENCY}" "Invalid bash version format: '${bash_major}'"
  fi

  # Check minimum version requirement (bash 4.3+)
  if [[ "${bash_major}" -lt "${min_major}" ]] || \
     [[ "${bash_major}" -eq "${min_major}" && "${bash_minor}" -lt "${min_minor}" ]]; then
    error "${ERR_DEPENDENCY}" "Requires bash ${min_major}.${min_minor}+ for namerefs (current: ${BASH_VERSION})"
  fi

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Bash version ${BASH_VERSION} OK"
}

# ------------------------------------------------------------------------------
# Validate that all required tools are installed
# Usage: validate_tools
# ------------------------------------------------------------------------------
validate_tools() {
  local missing_tools=()

  for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "${tool}" &>/dev/null; then
      missing_tools+=("${tool}")
    fi
  done

  if [[ "${#missing_tools[@]}" -gt 0 ]]; then
    error "${ERR_DEPENDENCY}" "Missing required tools: ${missing_tools[*]}"
  fi

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "All required tools present"
}

# ------------------------------------------------------------------------------
# Validate value against list of valid options
# Usage: validate_value <value> <valid_list_array_name> <result_var_name>
# Example:
#   local is_valid
#   validate_value "${user_input}" VALID_OUTPUT_FORMATS is_valid
#   if ! ${is_valid}; then echo "Invalid"; fi
# ------------------------------------------------------------------------------
validate_value() {
  local value="${1}"
  declare -n valid_value_list_ref="${2}"
  declare -n valid_value_flag_ref="${3}"

  valid_value_flag_ref=false

  for item in "${valid_value_list_ref[@]}"; do
    if [[ "${value}" == "${item}" ]]; then
      valid_value_flag_ref=true
      break
    fi
  done

  debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Validated: ${value} -> ${valid_value_flag_ref}"
}

# ------------------------------------------------------------------------------
# Validate package name format
# Usage: validate_package_name <package_name>
# Returns: 0 if valid, 1 if invalid
# ------------------------------------------------------------------------------
validate_package_name() {
  local pkg="${1}"

  debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "Validating package name: '${pkg}'"

  # NPM package name rules:
  # - Scoped packages: @scope/name
  # - Unscoped packages: name
  # - Allowed chars: lowercase letters, digits, hyphens, underscores, dots, tildes
  # - Cannot contain: spaces, special chars, uppercase letters
  # Reference: https://docs.npmjs.com/cli/v9/configuring-npm/package-json#name

  # Check for nested node_modules paths (invalid)
  if [[ "${pkg}" == *"/node_modules/"* ]]; then
    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Invalid package (nested): ${pkg}"
    return 1
  fi

  # Validate package name format (scoped or unscoped)

  # Use variable for regex to avoid bash parsing issues with special characters
  # Note: Hyphens must be at the END of character classes to be treated as literals
  # [a-z0-9-~] would try to create a range from - to ~, which is wrong
  # [a-z0-9~-] treats the hyphen as a literal character
  local regex_pattern="^(@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$"

  # When using the variable $pattern inside [[ ... ]], do not put quotes around it.
  # Quoting the variable there tells Bash to treat it as a literal string rather
  # than a RegEx.
  if [[ "${pkg}" =~ $regex_pattern ]]; then
    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Valid package name: ${pkg}"
    return 0
  else
    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Invalid package name format: ${pkg}"
    return 1
  fi
}

# ------------------------------------------------------------------------------
# Validate directory path
# Usage: validate_directory_path <path>
# Returns: 0 if valid, 1 if invalid
# ------------------------------------------------------------------------------
validate_directory_path() {
  local dir_path="${1}"

  # Check for path traversal attempts
  if [[ "${dir_path}" == *".."* ]]; then
    debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Invalid path (traversal): ${dir_path}"
    return 1
  fi

  # Check for suspicious characters (only allow alphanumeric, /, -, _, ., ~, spaces)
  # Note: We allow spaces since directory names commonly contain them

  # But having a space inside [[ ... ]] causes Bash to sometimes expects it to be a
  # separator between arguments rather than a character to match, especially if the
  # regex isn't handled as a single string, leading to word splitting or improper
  # escaping within the bracket expression.

  # To get around that, we put the RegEx expression in a variable -- bypassing the
  # shell's attempt to parse the special characters (e.g. spaces or hyphens) inside
  # the if statement.

  local regex_pattern="^[a-zA-Z0-9/_ .~-]+$"
  if [[ ! "${dir_path}" =~ $regex_pattern ]]; then
    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Invalid path (suspicious chars): ${dir_path}"
    return 1
  fi

  debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Valid directory path: ${dir_path}"
  return 0
}

# ------------------------------------------------------------------------------
# Cleanup function called on exit
# ------------------------------------------------------------------------------
cleanup() {
  # Currently, there is no need for any cleanup (e.g. no temp files to remove,
  # no connections to close, etc.). But this is here as a placeholder for good
  # program design.
  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Cleanup completed"
}

# ==============================================================================
# Core Scanning Functions
# ==============================================================================

# ------------------------------------------------------------------------------
# Build associative array of direct dependencies from package-lock.json. This is
# to more easily identify which packages have direct dependency, versus packages
# that are transitively dependent. Could be useful when discussing with
# developers.
# Usage: build_direct_deps_map <lockfile_path>
# Sets: direct_deps_map (global associative array)
# ------------------------------------------------------------------------------
build_direct_deps_map() {
  local lockfile_path="${1}"

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Building direct dependencies map from ${lockfile_path}"

  # Associative arrays provide O(1) lookup time vs O(n) for grep
  # This is crucial when checking 200+ packages against 10-50 direct deps
  # Note: direct_deps_map is declared globally at top of script

  # Clear the associative array for this project
  direct_deps_map=()

  # Extract direct dependencies from package-lock.json
  # Unlike package.json, package-lock.json has the exact dependency tree & exact
  # package versions installed

  # We look at packages with depth 1 (direct dependencies only)
  while IFS= read -r dep; do
    direct_deps_map["${dep}"]="${DIRECT_DEPENDENCY}"
    debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "Added direct dependency: ${dep}"
  done < <(jq -r '.packages | to_entries[] |
                  select(.key | startswith("'"${NODE_MODULES_PREFIX}"'") and
                         (. | split("/") | length) == 2) |
                  .key | sub("'"${NODE_MODULES_PREFIX}"'"; "")' "${lockfile_path}" 2>/dev/null)

  # Explanation of jq command:
  #   .packages                        -> Access packages object
  #   | to_entries[]                   -> Convert to array of {key, value} pairs
  #   | select(.key | startswith(...)) -> Only packages in node_modules/ at depth 1
  #   | .key | sub(...)                -> Remove "node_modules/" prefix

  # The depth check explained using examples below:
  #   "node_modules/express"                           -> split("/") = ["node_modules", "express"]          -> length = 2 -> DIRECT
  #   "node_modules/express/node_modules/body-parser"  -> split("/") = ["node_modules", "express", ...]     -> length = 4 -> nested

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Built map with ${#direct_deps_map[@]} direct dependencies"
}

# ------------------------------------------------------------------------------
# Convert ISO 8601 date to Unix timestamp (Linux)
# Usage: convert_iso_to_timestamp <iso_date>
# Outputs: Unix timestamp to stdout
# Returns: 0 on success, 1 on failure
# Note: Uses Linux date command syntax (-d flag)
# ------------------------------------------------------------------------------
convert_iso_to_timestamp() {
  local iso_date="${1}"
  local timestamp=""

  # Remove milliseconds: "2026-03-20T14:30:45.123Z" -> "2026-03-20T14:30:45"
  local date_without_ms="${iso_date%.*}"

  # Linux date command with -d flag for date parsing
  timestamp=$(date -d "${date_without_ms}" "+%s" 2>/dev/null) || return 1

  echo "${timestamp}"
  return 0
}

# ------------------------------------------------------------------------------
# Scan packages in a single project. Scans all packages, regardless if the packages
# are directly dependent or transitively independent.
# Usage: scan_project_packages <lockfile_path> <project_index>
# Returns: 0 if packages found within threshold, 1 if none found
# Sets: project_total_packages[project_index], project_flagged_packages[project_index]
# Note: Returns count of flagged packages via global total_flagged counter
# ------------------------------------------------------------------------------
scan_project_packages() {
  local lockfile_path="${1}"
  local project_index="${2}"
  local package_flagged_count=0
  local project_package_count=0

  # "flagged_list" will contain pipe-delimited strings of packages that have been flagged for review.
  # Format: "package@version|type|publish_date|age_hours"
  # Multiple packages are separated by newlines:
  # - easy for "grep -c" to count
  # - works well with "while read -r line" loops
  # - already output format ready (just needs parsing)
  # - no special escaping needed for package names with uncommon characters
  # Each discovered "package-lock.json" will have its own "flagged_list" entry in the array "project_flagged_packages"
  local flagged_list=""

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Scanning packages in ${lockfile_path}"

  # Extract all installed packages from package-lock.json
  # This includes direct dependencies AND nested dependencies (transitive deps)
  # Note: Using '|' as delimiter instead of '@' because scoped packages like @esbuild/aix-ppc64
  # contain '@' in their name. Using '@' as delimiter would incorrectly split @esbuild/aix-ppc64@0.27.3
  # into pkg='' version='esbuild/aix-ppc64@0.27.3' instead of pkg='@esbuild/aix-ppc64' version='0.27.3'
  while IFS='|' read -r pkg version; do
    ((project_package_count += 1))
    # IFS='|' sets the Input Field Separator to '|'
    # This splits "@esbuild/aix-ppc64|0.27.3" into:
    #   pkg = "@esbuild/aix-ppc64"
    #   version = "0.27.3"

    debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "Processing ${pkg}@${version}"

    # Validate package name
    if ! validate_package_name "${pkg}"; then
      debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Skipping invalid package: ${pkg}"
      continue
    fi

    # Determine if this is a direct or nested dependency
    # OPTIMIZATION: O(1) hash lookup instead of O(n) grep search
    local is_direct
    if [[ -n "${direct_deps_map[${pkg}]:-}" ]]; then
      is_direct="[DIRECT]"
    else
      is_direct="[nested]"
    fi

    # Query npm registry for publish date of this SPECIFIC version
    # PERFORMANCE NOTE: This is the main bottleneck in the scanning process
    # Performance testing showed:
    #   - npm view query: ~790ms average per package (51 seconds for 65 packages)
    #   - jq extraction: ~8ms per project (negligible)
    #   - date conversion: ~5ms per package (negligible)
    # For projects with many packages, this network query dominates execution time.
    #
    # OPTIMIZATION: Cache npm view results across projects
    # Many packages (express, lodash, etc.) appear in multiple projects with the same version.
    # Caching package@version -> publish_date eliminates redundant network calls.
    local cache_key="${pkg}@${version}"
    local publish_date

    if [[ -n "${npm_cache[${cache_key}]:-}" ]]; then
      # Cache hit - use cached publish date
      publish_date="${npm_cache[${cache_key}]}"
      ((cache_hits += 1))
      debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "Cache HIT for ${cache_key}"
    else
      # Cache miss - query npm registry
      publish_date=$(npm view "${pkg}@${version}" time --json 2>/dev/null | \
                     jq -r ".\"${version}\"" 2>/dev/null) || continue

      # Store in cache for future lookups
      if [[ -n "${publish_date}" ]] && [[ "${publish_date}" != "null" ]]; then
        npm_cache[${cache_key}]="${publish_date}"
      fi
      ((cache_misses += 1))
      debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "Cache MISS for ${cache_key}, queried npm"
    fi

    # Check if we got a valid publish date
    if [[ -n "${publish_date}" ]] && [[ "${publish_date}" != "null" ]]; then

      # Convert ISO 8601 date to Unix timestamp
      local pkg_timestamp
      pkg_timestamp=$(convert_iso_to_timestamp "${publish_date}") || continue

      # Calculate package age in hours
      local age_hours
      age_hours=$(( (current_timestamp - pkg_timestamp) / SECONDS_PER_HOUR ))

      debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "${lockfile_path}:${pkg}@${version} published: ${publish_date} age: ${age_hours} hours"

      # If package is published within threshold
      if [[ "${age_hours}" -lt "${age_threshold_hours}" ]]; then
        ((package_flagged_count += 1))

        # Add to flagged list for this project (pipe-delimited format)
        local flagged_entry="${pkg}@${version}|${is_direct}|${publish_date}|${age_hours}"
        if [[ -z "${flagged_list}" ]]; then
          flagged_list="${flagged_entry}"
        else
          flagged_list="${flagged_list}"$'\n'"${flagged_entry}"
        fi
      fi
    fi

  done < <(jq -r '.packages | to_entries[] | select(.key != "") |
                  (.key | sub("'"${NODE_MODULES_PREFIX}"'"; "")) + "|" + .value.version' "${lockfile_path}" 2>/dev/null)

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Found ${package_flagged_count} packages within threshold"

  # Store per-project statistics
  project_total_packages[project_index]="${project_package_count}"
  project_flagged_packages[project_index]="${flagged_list}"

  # Return success if packages were flagged, failure otherwise
  # This allows caller to check return code instead of relying on exit code for count
  if [[ "${package_flagged_count}" -gt 0 ]]; then
    return 0  # Has flagged packages
  else
    return 1  # No flagged packages
  fi
}

# ------------------------------------------------------------------------------
# Extract project name from package-lock.json
# Usage: get_project_name <lockfile_path>
# Outputs: Project name to stdout
# ------------------------------------------------------------------------------
get_project_name() {
  local lockfile_path="${1}"
  local project_name

  # Extract project name from package-lock.json (preferred source of truth)
  # package-lock.json contains the "name" field at the root level
  project_name=$(jq -r '.name // "unknown"' "${lockfile_path}" 2>/dev/null)

  # If not found in package-lock.json, fallback to directory name
  if [[ "${project_name}" == "unknown" ]] || [[ -z "${project_name}" ]]; then
    project_name=$(basename "$(dirname "${lockfile_path}")")
  fi

  echo "${project_name}"
}

# ------------------------------------------------------------------------------
# Scan all projects in directory tree
# Usage: scan_projects <search_dir> <age_threshold_hours>
# Sets: total_projects, total_flagged, projects_with_issues (global counters)
# ------------------------------------------------------------------------------
scan_projects() {
  # Reset global statistics counters
  # These are declared globally at top of script for clarity and bash 3.2 compatibility
  total_projects=0
  total_flagged=0
  projects_with_issues=0
  cache_hits=0
  cache_misses=0

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Searching for projects in ${search_dir}"

  # Find all directories containing package-lock.json
  # IMPORTANT: Use process substitution (< <(...)) instead of pipe (|)
  # to avoid subshell issues where variable updates are lost

  # "IFS=": Set Input Field Separator to empty (prevents word splitting)
  # "-r": Raw mode (don't interpret backslashes)

  while IFS= read -r lockfile; do
    # Increment project counter
    ((total_projects += 1))

    # --------------------------------------------------------------------------
    # Directory handling: Convert to absolute path and change to project directory
    # --------------------------------------------------------------------------

    # Convert lockfile path to absolute path
    # This eliminates the need to track and return to starting directory
    local abs_lockfile
    abs_lockfile=$(realpath "${lockfile}")
    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Project package-lock.json: ${abs_lockfile}"

    # Get the directory containing the lockfile (now absolute)
    local abs_project_dir
    abs_project_dir=$(dirname "${abs_lockfile}")

    # Validate directory path for security
    if ! validate_directory_path "${abs_project_dir}"; then
      debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Skipping suspicious path: ${abs_project_dir}"
      continue
    fi

    # Change to project directory (required for npm commands to work correctly)
    # Since project_dir is now absolute, this always works regardless of current directory
    if ! cd "${abs_project_dir}"; then
      debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Cannot access directory: ${abs_project_dir}"
      continue
    fi

    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Changed to: ${abs_project_dir}"

    # --------------------------------------------------------------------------
    # Project processing: Extract name and scan packages
    # --------------------------------------------------------------------------

    # Extract project name from package-lock.json (more reliable than package.json)
    local project_name
    project_name=$(get_project_name "${abs_lockfile}")
    debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Scanning project: ${project_name}"

    # Store project information (using array index = total_projects - 1)
    local project_index=$((total_projects - 1))
    project_names[project_index]="${project_name}"
    project_paths[project_index]="${abs_project_dir}"

    debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Scanning project: ${abs_project_dir}"

    # Build associative array of direct dependencies
    build_direct_deps_map "${abs_lockfile}"

    # Scan all packages in this project
    if scan_project_packages "${abs_lockfile}" "${project_index}"; then
      # Calculate count of flagged packages from stored list
      local package_flagged_count
      if [[ -n "${project_flagged_packages[project_index]}" ]]; then
        package_flagged_count=$(echo "${project_flagged_packages[project_index]}" | grep -c '^')
      else
        package_flagged_count=0
      fi

      debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Found ${package_flagged_count} recent package(s) in ${abs_project_dir}"
      ((projects_with_issues += 1))
      ((total_flagged += package_flagged_count))
    else
      debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "No recent packages found in ${abs_project_dir}"
    fi

  done < <(find "${abs_search_dir}" -type f -name "package-lock.json" 2>/dev/null)

  # Explanation:
  #   find ... 2>/dev/null            -> Suppress "Permission denied" errors
  #   done < <(find ...)              -> Process substitution avoids subshell
  #                                      This ensures counters are updated correctly
  #   Using absolute paths (realpath) -> No need to track/return to starting directory

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Scanned ${total_projects} projects"

  # Cache performance statistics
  local total_queries=$((cache_hits + cache_misses))
  if [[ "${total_queries}" -gt 0 ]]; then
    local cache_hit_rate=$((cache_hits * 100 / total_queries))
    debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Cache statistics: ${cache_hits} hits, ${cache_misses} misses, ${total_queries} total, ${cache_hit_rate}% hit rate"
  fi
}

# ==============================================================================
# Output & Display Functions
# ==============================================================================

# ------------------------------------------------------------------------------
# Iterate through all flagged packages and call a callback function for each
# Usage: iterate_flagged_packages <callback_function>
# Callback signature: callback <project_index> <pkg_version> <dep_type> <pub_date> <age_hours>
# ------------------------------------------------------------------------------
iterate_flagged_packages() {
  local callback="${1}"

  debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Iterating flagged packages with callback: ${callback}"

  # Iterate through all projects
  for i in $(seq 0 $((total_projects - 1))); do
    local flagged="${project_flagged_packages[i]}"

    # Skip projects with no flagged packages
    if [[ -z "${flagged}" ]]; then
      continue
    fi

    # Parse each pipe-delimited line and call the callback
    while IFS='|' read -r pkg_version dep_type pub_date age_hrs; do
      # Call the callback with parsed fields
      "${callback}" "${i}" "${pkg_version}" "${dep_type}" "${pub_date}" "${age_hrs}"
    done <<< "${flagged}"
  done
}

# ------------------------------------------------------------------------------
# Output callback for CSV format
# Usage: _csv_callback <project_index> <pkg_version> <dep_type> <pub_date> <age_hours>
# ------------------------------------------------------------------------------
_csv_callback() {
  local proj_idx="${1}"
  local pkg_version="${2}"
  local dep_type="${3}"
  local pub_date="${4}"
  local age_hrs="${5}"

  local lockfile_path="${project_paths[proj_idx]}/package-lock.json"
  local project_name="${project_names[proj_idx]}"
  echo "${lockfile_path},${project_name},${pkg_version},${dep_type},${pub_date},${age_hrs}"
}

# ------------------------------------------------------------------------------
# Output all flagged packages in CSV format
# Format: lockfile_path,project_name,package@version,type,publish_date,age_hours
# ------------------------------------------------------------------------------
output_csv() {
  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Outputting CSV format"
  iterate_flagged_packages _csv_callback
}

# ------------------------------------------------------------------------------
# Output callback for JSONL format (JSON Lines - one object per line)
# Usage: _jsonl_callback <project_index> <pkg_version> <dep_type> <pub_date> <age_hours>
# ------------------------------------------------------------------------------
_jsonl_callback() {
  local proj_idx="${1}"
  local pkg_version="${2}"
  local dep_type="${3}"
  local pub_date="${4}"
  local age_hrs="${5}"

  local lockfile_path="${project_paths[proj_idx]}/package-lock.json"
  local project_name="${project_names[proj_idx]}"

  # Output single JSON object per line (properly escaped, monochrome for automation)
  jq -M -n \
    --arg lockfile "${lockfile_path}" \
    --arg project "${project_name}" \
    --arg package "${pkg_version}" \
    --arg type "${dep_type}" \
    --arg published "${pub_date}" \
    --argjson age_hours "${age_hrs}" \
    '{lockfile: $lockfile, project: $project, package: $package, type: $type, published: $published, age_hours: $age_hours}'
}

# ------------------------------------------------------------------------------
# Output all flagged packages in JSONL format (one JSON object per line)
# ------------------------------------------------------------------------------
output_jsonl() {
  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Outputting JSONL format"
  iterate_flagged_packages _jsonl_callback
}

# ------------------------------------------------------------------------------
# Output all flagged packages in JSON array format
# Format: Single JSON array containing all flagged packages
# ------------------------------------------------------------------------------
output_json_array() {
  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Outputting JSON array format"

  local first_item=true
  echo "["

  # Define inline callback for array items
  # shellcheck disable=SC2329
  _json_array_callback() {
    local proj_idx="${1}"
    local pkg_version="${2}"
    local dep_type="${3}"
    local pub_date="${4}"
    local age_hrs="${5}"

    local lockfile_path="${project_paths[proj_idx]}/package-lock.json"
    local project_name="${project_names[proj_idx]}"

    # Add comma before all items except the first
    if [[ "${first_item}" == "true" ]]; then
      first_item=false
    else
      echo ","
    fi

    # Output JSON object (properly indented, monochrome for automation compatibility)
    jq -M -n \
      --arg lockfile "${lockfile_path}" \
      --arg project "${project_name}" \
      --arg package "${pkg_version}" \
      --arg type "${dep_type}" \
      --arg published "${pub_date}" \
      --argjson age_hours "${age_hrs}" \
      '{lockfile: $lockfile, project: $project, package: $package, type: $type, published: $published, age_hours: $age_hours}' | \
      sed 's/^/  /'
  }

  iterate_flagged_packages _json_array_callback
  echo "]"
}

# ------------------------------------------------------------------------------
# Output structured JSON with metadata and per-project breakdown
# Format: Complete scan results with summary statistics and project details
# ------------------------------------------------------------------------------
output_json_structured() {
  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Outputting structured JSON format"

  # Build projects array with flagged packages
  local projects_json="["
  local first_project=true

  for i in $(seq 0 $((total_projects - 1))); do
    local project_name="${project_names[i]}"
    local project_path="${project_paths[i]}"
    local total_pkgs="${project_total_packages[i]}"
    local flagged="${project_flagged_packages[i]}"

    # Count flagged packages for this project
    local flagged_count=0
    if [[ -n "${flagged}" ]]; then
      flagged_count=$(echo "${flagged}" | grep -c '^')
    fi

    # Add comma between projects
    if [[ "${first_project}" == "true" ]]; then
      first_project=false
    else
      projects_json="${projects_json},"
    fi

    # Build flagged_packages array for this project
    local flagged_packages_json="["
    if [[ -n "${flagged}" ]]; then
      local first_pkg=true
      while IFS='|' read -r pkg_version dep_type pub_date age_hrs; do
        if [[ "${first_pkg}" == "true" ]]; then
          first_pkg=false
        else
          flagged_packages_json="${flagged_packages_json},"
        fi

        # Add package object
        local pkg_obj
        pkg_obj=$(jq -n \
          --arg package "${pkg_version}" \
          --arg type "${dep_type}" \
          --arg published "${pub_date}" \
          --argjson age_hours "${age_hrs}" \
          '{package: $package, type: $type, published: $published, age_hours: $age_hours}')
        flagged_packages_json="${flagged_packages_json}${pkg_obj}"
      done <<< "${flagged}"
    fi
    flagged_packages_json="${flagged_packages_json}]"

    # Build project object
    local project_obj
    project_obj=$(jq -n \
      --arg name "${project_name}" \
      --arg path "${project_path}" \
      --argjson total_packages "${total_pkgs}" \
      --argjson flagged_count "${flagged_count}" \
      --argjson flagged_packages "${flagged_packages_json}" \
      '{name: $name, path: $path, total_packages: $total_packages, flagged_count: $flagged_count, flagged_packages: $flagged_packages}')

    projects_json="${projects_json}${project_obj}"
  done
  projects_json="${projects_json}]"

  # Calculate cache statistics
  local total_queries=$((cache_hits + cache_misses))
  local cache_hit_rate=0
  if [[ "${total_queries}" -gt 0 ]]; then
    cache_hit_rate=$((cache_hits * 100 / total_queries))
  fi

  # Build complete JSON structure (monochrome for automation compatibility)
  jq -M -n \
    --argjson scan_timestamp "${current_timestamp}" \
    --argjson threshold_hours "${age_threshold_hours}" \
    --arg search_dir "${abs_search_dir}" \
    --argjson total_projects "${total_projects}" \
    --argjson projects_with_issues "${projects_with_issues}" \
    --argjson total_flagged "${total_flagged}" \
    --argjson cache_hits "${cache_hits}" \
    --argjson cache_misses "${cache_misses}" \
    --argjson cache_hit_rate "${cache_hit_rate}" \
    --argjson projects "${projects_json}" \
    '{
      scan_metadata: {
        scan_timestamp: $scan_timestamp,
        threshold_hours: $threshold_hours,
        search_directory: $search_dir
      },
      summary: {
        total_projects: $total_projects,
        projects_with_issues: $projects_with_issues,
        total_packages_flagged: $total_flagged
      },
      performance: {
        cache_hits: $cache_hits,
        cache_misses: $cache_misses,
        cache_hit_rate_percent: $cache_hit_rate
      },
      projects: $projects
    }'
}

# ------------------------------------------------------------------------------
# Display scan header with search parameters
# ------------------------------------------------------------------------------
disp_header() {
  echo ""
  echo "Finding all npm projects under: ${search_dir}"
  echo "Threshold: Packages published within last ${age_threshold_hours} hours"
  echo "Current date & time: $(date -d "@$current_timestamp" "+%Y-%m-%d %H:%M:%S %Z")"
  echo ""
  echo "================================================================"
  echo "                      SCAN SUMMARY"
  echo "================================================================"
  echo ""
}

# ------------------------------------------------------------------------------
# Display details for a single project
# Usage: disp_project_details <proj_number> <proj_name> <proj_path> <proj_total> <proj_flagged>
# ------------------------------------------------------------------------------
disp_project_details() {
  local proj_number="${1}"
  local proj_name="${2}"
  local proj_path="${3}"
  local proj_total="${4}"
  local proj_flagged="${5}"

  echo "  ${proj_number}. ${proj_name}"
  echo "     Path: ${proj_path}"
  echo "     Total packages: ${proj_total}"

  if [[ -n "${proj_flagged}" ]]; then
    echo "     Flagged packages:"
    while IFS= read -r pkg_version; do
      echo "       - ${pkg_version}"
    done <<< "${proj_flagged}"
  else
    echo "     Flagged packages: None"
  fi
  echo ""
}

# ------------------------------------------------------------------------------
# Display final summary statistics
# ------------------------------------------------------------------------------
disp_final_summary() {
  echo "----------------------------------------------------------------"
  echo "Final Summary:"
  echo "----------------------------------------------------------------"
  echo ""
  echo "  Projects scanned:         ${total_projects}"
  echo "  Projects with issues:     ${projects_with_issues}"
  echo "  Total packages flagged:   ${total_flagged}"
  echo "  Age threshold:            ${age_threshold_hours} hours"
  echo ""
}

# ------------------------------------------------------------------------------
# Display recommendations based on scan results
# ------------------------------------------------------------------------------
disp_recommendations() {
  if [[ "${total_flagged}" -eq 0 ]]; then
    echo "PASS: All projects clear! No recently published packages found."
  else
    echo "WARN: Review flagged packages above for potential security risks."
    echo ""
    echo "Recommended actions:"
    echo "  - Research the package maintainer and recent changes"
    echo "  - Check GitHub/npm for suspicious activity"
    echo "  - Consider pinning versions until packages mature"
    echo "  - Run 'npm audit' for known vulnerabilities"
  fi
  echo ""
}

# ------------------------------------------------------------------------------
# Display complete scan summary
# ------------------------------------------------------------------------------
disp_summary() {
  disp_header

  # Display per-project details
  if [[ "${total_projects}" -gt 0 ]]; then
    echo "Projects Scanned:"
    echo ""

    for i in $(seq 0 $((total_projects - 1))); do
      disp_project_details \
        "$((i + 1))" \
        "${project_names[i]}" \
        "${project_paths[i]}" \
        "${project_total_packages[i]}" \
        "${project_flagged_packages[i]}"
    done
  fi

  disp_final_summary
  disp_recommendations
}

# ==============================================================================
# Main Function
# ==============================================================================

main() {
  # Parse command line arguments for -o flag
  if [[ "${1:-}" == "-o" ]]; then
    # Convert to lowercase for case-insensitive comparison (POSIX-compliant approach)
    local format="${2:-}"
    format="$(echo "${format}" | tr '[:upper:]' '[:lower:]')"

    # Validate output format using validate_value function
    local is_valid_format
    validate_value "${format}" VALID_OUTPUT_FORMATS is_valid_format

    if ${is_valid_format}; then
      OUTPUT_FORMAT="${format}"
      shift 2  # Remove -o and format from arguments
    else
      error "${ERR_CONFIG}" "Invalid output format '${2}'. Must be one of: ${VALID_OUTPUT_FORMATS[*]} (case-insensitive)"
    fi
  fi

  # Parse remaining positional arguments
  search_dir="${1:-$DEFAULT_DIRECTORY}"                                                            # If $1 is empty or unset, use $DEFAULT_DIRECTORY
  age_threshold_hours="${2:-$DEFAULT_AGE_THRESHOLD_HOURS}"                                         # If $2 is empty or unset, use $DEFAULT_AGE_THRESHOLD_HOURS

  # Setup trap for cleanup
  trap cleanup EXIT INT TERM

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Starting ${SCRIPT_NAME}"

  # Validate OUTPUT_FORMAT early (in case it was set via environment variable)
  local is_valid_output_format
  validate_value "${OUTPUT_FORMAT}" VALID_OUTPUT_FORMATS is_valid_output_format

  if ! ${is_valid_output_format}; then
    error "${ERR_CONFIG}" "Invalid OUTPUT_FORMAT environment variable '${OUTPUT_FORMAT}'. Must be one of: ${VALID_OUTPUT_FORMATS[*]}"
  fi

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Output format: ${OUTPUT_FORMAT}"

  # Validate search directory exists
  if [[ ! -d "${search_dir}" ]]; then
    error "${ERR_CONFIG}" "Directory '${search_dir}' does not exist"
  fi

  # Convert search_dir to absolute path so find command will return absolute paths
  abs_search_dir=$(realpath "${search_dir}")

  # Validate that age threshold is a positive integer
  if ! [[ "${age_threshold_hours}" =~ ^[0-9]+$ ]]; then
    error "${ERR_CONFIG}" "Age threshold must be a positive integer (hours)"
  fi

  # Validate maximum value (prevent integer overflow)
  if [[ "${age_threshold_hours}" -gt "${MAX_AGE_THRESHOLD_HOURS}" ]]; then
    error "${ERR_CONFIG}" "Age threshold too large (max: ${MAX_AGE_THRESHOLD_HOURS} hours)"
  fi

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Search directory: ${abs_search_dir}"
  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Age threshold: ${age_threshold_hours} hours"

  # Pre-flight checks
  validate_bash_version
  validate_tools

  # Scan all projects
  scan_projects

  # Output results based on mode and format
  if [[ "${HEADLESS}" == "true" ]]; then
    # Using associative arrays to reduce the use of nested/convoluted if-else statements or case statements
    declare -A output_function
    output_function["csv"]="output_csv"
    output_function["jsonl"]="output_jsonl"
    output_function["json-array"]="output_json_array"
    output_function["json-structured"]="output_json_structured"

    # Lookup and call the output function (validation already done early, so this should always succeed)
    local func_name="${output_function[${OUTPUT_FORMAT}]}"
    "${func_name}"
  else
    # Interactive mode: human-readable summary
    disp_summary
  fi

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Script completed successfully"
}

# ==============================================================================
# Entry Point
# ==============================================================================

# Only run main if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
