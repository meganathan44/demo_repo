#!/usr/bin/env python3

import os
import sys
import subprocess
import json
import re
from typing import Dict, List
from pathlib import Path
import shutil
from packaging import version

def is_tool_available(name: str) -> bool:
    """Check if a command-line tool is available."""
    return shutil.which(name) is not None

def detect_package_managers(repo_dir: str) -> Dict[str, str]:
    """Detect package managers based on dependency files."""
    package_files = {
        'package.json': 'npm',
        'requirements.txt': 'pip',
        'Pipfile': 'pipenv',
        'composer.json': 'composer',
        'pom.xml': 'maven',
        'build.gradle': 'gradle',
        'Gemfile': 'bundler',
        'go.mod': 'go',
        'Cargo.toml': 'cargo',
        '*.csproj': 'dotnet'
    }

    found_managers = {}
    
    for file_pattern, manager in package_files.items():
        if '*' in file_pattern:
            matches = list(Path(repo_dir).rglob(file_pattern.replace('*', '*')))
            if matches:
                found_managers[manager] = str(matches[0])
        else:
            file_path = os.path.join(repo_dir, file_pattern)
            if os.path.exists(file_path):
                found_managers[manager] = file_path

    return found_managers

def check_npm_packages(repo_dir: str) -> List[Dict]:
    """Check NPM packages for updates."""
    packages = []
    if not is_tool_available('npm'):
        return packages

    try:
        with open(os.path.join(repo_dir, 'package.json'), 'r') as f:
            pkg_data = json.load(f)
            all_deps = {}
            all_deps.update(pkg_data.get('dependencies', {}))
            all_deps.update(pkg_data.get('devDependencies', {}))

        for pkg_name, current_version in all_deps.items():
            current_version = current_version.replace('^', '').replace('~', '')
            try:
                result = subprocess.run(
                    ['npm', 'view', pkg_name, 'version'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                latest_version = result.stdout.strip()
                packages.append({
                    'name': pkg_name,
                    'current': current_version,
                    'latest': latest_version
                })
            except subprocess.CalledProcessError:
                continue

    except Exception as e:
        print(f"Error checking NPM packages: {e}")

    return packages

def check_pip_packages(requirements_path: str) -> List[Dict]:
    """Check Python packages for updates."""
    packages = []
    if not os.path.exists(requirements_path):
        return packages

    try:
        with open(requirements_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse requirement line
                    match = re.match(r'^([^=<>]+)(==|>=|<=|~=|!=|<|>)?(.+)?', line)
                    if match:
                        pkg_name = match.group(1).strip()
                        current_version = match.group(3).strip() if match.group(3) else "Not specified"
                        
                        try:
                            result = subprocess.run(
                                ['pip', 'index', 'versions', pkg_name],
                                capture_output=True,
                                text=True,
                                check=True
                            )
                            versions = re.findall(r'\d+\.\d+\.\d+', result.stdout)
                            if versions:
                                latest_version = max(versions, key=lambda x: version.parse(x))
                                packages.append({
                                    'name': pkg_name,
                                    'current': current_version,
                                    'latest': latest_version
                                })
                        except subprocess.CalledProcessError:
                            continue

    except Exception as e:
        print(f"Error checking pip packages: {e}")

    return packages

def main():
    repo_dir = os.getcwd()
    results = {}
    
    # Detect package managers
    package_managers = detect_package_managers(repo_dir)
    
    # Check packages for each detected package manager
    for manager, file_path in package_managers.items():
        if manager == 'npm':
            results['npm'] = check_npm_packages(repo_dir)
        elif manager == 'pip':
            results['pip'] = check_pip_packages(file_path)
        # Add more package manager checks as needed
    
    # Write results to a JSON file
    with open('dependency-report.json', 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main() 
