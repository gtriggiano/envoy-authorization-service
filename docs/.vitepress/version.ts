import { execSync } from 'child_process'
import { readFileSync } from 'fs'
import { join } from 'path'

/**
 * Gets the latest version from git tags.
 * 
 * This module automatically detects the project version from git tags,
 * which allows the documentation to always reference the correct version
 * without manual updates.
 * 
 * Version detection strategy:
 * 1. First tries to get the latest git tag using `git describe --tags --abbrev=0`
 * 2. Removes the 'v' prefix if present (e.g., 'v1.0.3' becomes '1.0.3')
 * 3. Falls back to the VERSION file in the project root if git is unavailable
 * 4. Uses '1.0.0' as a last resort default
 * 
 * This works in both local development and CI environments, as long as:
 * - Git history is available (fetch-depth: 0 in CI)
 * - Tags are fetched (fetch-tags: true in CI)
 * 
 * @returns The detected version string without 'v' prefix
 */
export function getVersion(): string {
  try {
    // Try to get the latest tag from git
    const version = execSync('git describe --tags --abbrev=0', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim()
    
    // Remove 'v' prefix if present
    return version.startsWith('v') ? version.slice(1) : version
  } catch (error) {
    // Fallback to VERSION file in the root
    try {
      const versionFile = join(process.cwd(), '..', 'VERSION')
      return readFileSync(versionFile, 'utf-8').trim()
    } catch (fallbackError) {
      console.warn('Could not determine version from git or VERSION file, using default')
      return '1.0.0'
    }
  }
}

export const version = getVersion()
