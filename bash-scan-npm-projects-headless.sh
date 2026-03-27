#!/bin/bash
# Multi-Project NPM Security Scanner - Headless Version
# Usage: ./bash-scan-npm-projects-headless.sh [SEARCH_DIR] [HOURS]

set -euo pipefail

# Constants
readonly SCRIPT_NAME="$(basename "${0}")"
readonly ERR_CONFIG=1
readonly ERR_DEPENDENCY=2
readonly ERR_RUNTIME=3
readonly DEBUG_LEVEL_1=1
readonly DEBUG_LEVEL_2=2
readonly DEBUG_LEVEL_3=3
DEBUG="${DEBUG:-0}"
readonly SECONDS_PER_HOUR=3600
readonly MAX_AGE_THRESHOLD_HOURS=1000000
readonly NODE_MODULES_PREFIX="node_modules/"
readonly DIRECT_DEPENDENCY=1
readonly REQUIRED_TOOLS=("jq" "npm" "date" "find" "basename" "dirname")
readonly DEFAULT_DIRECTORY="/"
readonly DEFAULT_AGE_THRESHOLD_HOURS=24

# Global state
search_dir=""
abs_search_dir=""
age_threshold_hours=0
current_timestamp="$(date "+%s")"
declare -A direct_deps_map
declare -A npm_cache
total_projects=0
total_flagged=0
projects_with_issues=0
cache_hits=0
cache_misses=0
declare -a project_names=()
declare -a project_paths=()
declare -a project_total_packages=()
declare -a project_flagged_packages=()

# Error handler - outputs to stdout for remote execution compatibility
error() {
  local exit_code="${1}"
  local message="${2}"
  echo "Error: ${message}"
  exit "${exit_code}"
}

# Debug output to stderr
debug() {
  local dbg_level="${1}"
  local dbg_source="${2}"
  local dbg_message="${3}"
  if [[ "${DEBUG}" -ge "${dbg_level}" ]]; then
    echo "[DEBUG ${dbg_level}:${dbg_source}] ${dbg_message}" >&2
  fi
}

# Validate required tools
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

# Validate package name
validate_package_name() {
  local pkg="${1}"
  debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "Validating package name: '${pkg}'"

  if [[ "${pkg}" == *"/node_modules/"* ]]; then
    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Invalid package (nested): ${pkg}"
    return 1
  fi

  local regex_pattern="^(@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$"
  if [[ "${pkg}" =~ $regex_pattern ]]; then
    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Valid package name: ${pkg}"
    return 0
  else
    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Invalid package name format: ${pkg}"
    return 1
  fi
}

# Validate directory path
validate_directory_path() {
  local dir_path="${1}"
  if [[ "${dir_path}" == *".."* ]]; then
    debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Invalid path (traversal): ${dir_path}"
    return 1
  fi
  local regex_pattern="^[a-zA-Z0-9/_ .~-]+$"
  if [[ ! "${dir_path}" =~ $regex_pattern ]]; then
    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Invalid path (suspicious chars): ${dir_path}"
    return 1
  fi
  debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Valid directory path: ${dir_path}"
  return 0
}

# Build direct dependencies map
build_direct_deps_map() {
  local lockfile_path="${1}"
  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Building direct dependencies map from ${lockfile_path}"
  direct_deps_map=()
  while IFS= read -r dep; do
    direct_deps_map["${dep}"]="${DIRECT_DEPENDENCY}"
    debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "Added direct dependency: ${dep}"
  done < <(jq -r '.packages | to_entries[] |
                  select(.key | startswith("'"${NODE_MODULES_PREFIX}"'") and
                         (. | split("/") | length) == 2) |
                  .key | sub("'"${NODE_MODULES_PREFIX}"'"; "")' "${lockfile_path}" 2>/dev/null)
  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Built map with ${#direct_deps_map[@]} direct dependencies"
}

# Convert ISO date to timestamp
convert_iso_to_timestamp() {
  local iso_date="${1}"
  local timestamp=""
  local date_without_ms="${iso_date%.*}"
  timestamp=$(date -d "${date_without_ms}" "+%s" 2>/dev/null) || return 1
  echo "${timestamp}"
  return 0
}

# Scan packages in a project
scan_project_packages() {
  local lockfile_path="${1}"
  local project_index="${2}"
  local package_flagged_count=0
  local project_package_count=0
  local flagged_list=""

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Scanning packages in ${lockfile_path}"

  # Note: Using '|' as delimiter instead of '@' because scoped packages like @esbuild/aix-ppc64
  # contain '@' in their name. Using '@' as delimiter would incorrectly split @esbuild/aix-ppc64@0.27.3
  # into pkg='' version='esbuild/aix-ppc64@0.27.3' instead of pkg='@esbuild/aix-ppc64' version='0.27.3'
  while IFS='|' read -r pkg version; do
    ((project_package_count += 1))
    debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "Processing ${pkg}@${version}"

    if ! validate_package_name "${pkg}"; then
      debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Skipping invalid package: ${pkg}"
      continue
    fi

    local is_direct
    if [[ -n "${direct_deps_map[${pkg}]:-}" ]]; then
      is_direct="[DIRECT]"
    else
      is_direct="[nested]"
    fi

    local cache_key="${pkg}@${version}"
    local publish_date

    if [[ -n "${npm_cache[${cache_key}]:-}" ]]; then
      publish_date="${npm_cache[${cache_key}]}"
      ((cache_hits += 1))
      debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "Cache HIT for ${cache_key}"
    else
      publish_date=$(npm view "${pkg}@${version}" time --json 2>/dev/null | \
                     jq -r ".\"${version}\"" 2>/dev/null) || continue
      if [[ -n "${publish_date}" ]] && [[ "${publish_date}" != "null" ]]; then
        npm_cache[${cache_key}]="${publish_date}"
      fi
      ((cache_misses += 1))
      debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "Cache MISS for ${cache_key}, queried npm"
    fi

    if [[ -n "${publish_date}" ]] && [[ "${publish_date}" != "null" ]]; then
      local pkg_timestamp
      pkg_timestamp=$(convert_iso_to_timestamp "${publish_date}") || continue
      local age_hours
      age_hours=$(( (current_timestamp - pkg_timestamp) / SECONDS_PER_HOUR ))
      debug "${DEBUG_LEVEL_3}" "${FUNCNAME[0]}:$LINENO" "${lockfile_path}:${pkg}@${version} published: ${publish_date} age: ${age_hours} hours"

      if [[ "${age_hours}" -lt "${age_threshold_hours}" ]]; then
        ((package_flagged_count += 1))
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
  project_total_packages[project_index]="${project_package_count}"
  project_flagged_packages[project_index]="${flagged_list}"

  if [[ "${package_flagged_count}" -gt 0 ]]; then
    return 0
  else
    return 1
  fi
}

# Extract project name from package-lock.json
get_project_name() {
  local lockfile_path="${1}"
  local project_name
  project_name=$(jq -r '.name // "unknown"' "${lockfile_path}" 2>/dev/null)
  if [[ "${project_name}" == "unknown" ]] || [[ -z "${project_name}" ]]; then
    project_name=$(basename "$(dirname "${lockfile_path}")")
  fi
  echo "${project_name}"
}

# Scan all projects
scan_projects() {
  total_projects=0
  total_flagged=0
  projects_with_issues=0
  cache_hits=0
  cache_misses=0

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Searching for projects in ${search_dir}"

  while IFS= read -r lockfile; do
    ((total_projects += 1))
    local abs_lockfile
    abs_lockfile=$(realpath "${lockfile}")
    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Project package-lock.json: ${abs_lockfile}"

    local abs_project_dir
    abs_project_dir=$(dirname "${abs_lockfile}")

    if ! validate_directory_path "${abs_project_dir}"; then
      debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Skipping suspicious path: ${abs_project_dir}"
      continue
    fi

    if ! cd "${abs_project_dir}"; then
      debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Cannot access directory: ${abs_project_dir}"
      continue
    fi

    debug "${DEBUG_LEVEL_2}" "${FUNCNAME[0]}:$LINENO" "Changed to: ${abs_project_dir}"

    local project_name
    project_name=$(get_project_name "${abs_lockfile}")
    debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Scanning project: ${project_name}"

    local project_index=$((total_projects - 1))
    project_names[project_index]="${project_name}"
    project_paths[project_index]="${abs_project_dir}"

    debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Scanning project: ${abs_project_dir}"
    build_direct_deps_map "${abs_lockfile}"

    if scan_project_packages "${abs_lockfile}" "${project_index}"; then
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

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Scanned ${total_projects} projects"

  local total_queries=$((cache_hits + cache_misses))
  if [[ "${total_queries}" -gt 0 ]]; then
    local cache_hit_rate=$((cache_hits * 100 / total_queries))
    debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Cache statistics: ${cache_hits} hits, ${cache_misses} misses, ${total_queries} total, ${cache_hit_rate}% hit rate"
  fi
}

# Output CSV format
output_csv() {
  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Outputting CSV format"

  if [[ "${total_flagged}" -eq 0 ]]; then
    echo "No data"
    return 0
  fi

  for i in $(seq 0 $((total_projects - 1))); do
    local flagged="${project_flagged_packages[i]}"
    if [[ -z "${flagged}" ]]; then
      continue
    fi
    while IFS='|' read -r pkg_version dep_type pub_date age_hrs; do
      local lockfile_path="${project_paths[i]}/package-lock.json"
      local project_name="${project_names[i]}"
      echo "${lockfile_path},${project_name},${pkg_version},${dep_type},${pub_date},${age_hrs}"
    done <<< "${flagged}"
  done
}

# Main function
main() {
  search_dir="${1:-$DEFAULT_DIRECTORY}"                                                            # If $1 is empty or unset, use $DEFAULT_DIRECTORY
  age_threshold_hours="${2:-$DEFAULT_AGE_THRESHOLD_HOURS}"                                         # If $2 is empty or unset, use $DEFAULT_AGE_THRESHOLD_HOURS

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Starting ${SCRIPT_NAME}"

  if [[ ! -d "${search_dir}" ]]; then
    error "${ERR_CONFIG}" "Directory '${search_dir}' does not exist"
  fi

  abs_search_dir=$(realpath "${search_dir}")

  if ! [[ "${age_threshold_hours}" =~ ^[0-9]+$ ]]; then
    error "${ERR_CONFIG}" "Age threshold must be a positive integer (hours)"
  fi

  if [[ "${age_threshold_hours}" -gt "${MAX_AGE_THRESHOLD_HOURS}" ]]; then
    error "${ERR_CONFIG}" "Age threshold too large (max: ${MAX_AGE_THRESHOLD_HOURS} hours)"
  fi

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Search directory: ${abs_search_dir}"
  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Age threshold: ${age_threshold_hours} hours"

  validate_tools
  scan_projects
  output_csv

  debug "${DEBUG_LEVEL_1}" "${FUNCNAME[0]}:$LINENO" "Script completed successfully"
}

main "$@"
