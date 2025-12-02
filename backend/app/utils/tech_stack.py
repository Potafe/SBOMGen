import os
import tempfile
import requests
import fnmatch
import logging

from typing import List, Dict, Optional
from git import Repo

logger = logging.getLogger(__name__)

def detect_tech_stack(repo_url: str, github_token: Optional[str] = None) -> List[str]:
    """
    Detect the tech stack of a GitHub repository by examining common project files.
    """
    logger.info(f"Starting tech stack detection for repo: {repo_url}")
    tech_stack = []
    
    try:
        parts = repo_url.rstrip('/').split('/')
        if len(parts) < 2:
            logger.warning(f"Invalid repo URL format: {repo_url}")
            return tech_stack
        owner, repo_name = parts[-2], parts[-1].rstrip('.git')
        logger.info(f"Extracted owner: {owner}, repo: {repo_name}")
        
        api_url = f"https://api.github.com/repos/{owner}/{repo_name}/contents"
        languages_url = f"https://api.github.com/repos/{owner}/{repo_name}/languages"
        logger.info(f"API URLs: contents={api_url}, languages={languages_url}")
        
        headers = {}
        if github_token:
            headers['Authorization'] = f'token {github_token}'
            logger.info("Using authenticated GitHub API requests")
        else:
            logger.warning("No GitHub token provided - private repositories will fail")
        
        indicators = {
            "python": ["requirements.txt", "setup.py", "Pipfile", "pyproject.toml", "poetry.lock", "environment.yml", "conda.yml"],
            "nodejs": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"],
            "java": ["pom.xml", "build.gradle", "build.gradle.kts", "build.xml", "settings.gradle"],
            "go": ["go.mod", "go.sum", "Gopkg.toml", "Gopkg.lock"],
            "rust": ["Cargo.toml", "Cargo.lock"],
            "dotnet": ["*.csproj", "*.fsproj", "*.vbproj", "*.sln", "nuget.config"],
            "ruby": ["Gemfile", "Gemfile.lock", "*.gemspec"],
            "php": ["composer.json", "composer.lock"],
            "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"],
            "kubernetes": ["*.yaml", "*.yml", "kustomization.yaml"],
            "terraform": ["*.tf", "*.tfvars", "terraform.tfstate"],
            "typescript": ["tsconfig.json", "*.ts", "*.tsx"],
            "react": ["package.json"],
            "vue": ["vue.config.js", "nuxt.config.js", "nuxt.config.ts"],
            "angular": ["angular.json", "ng-package.json"],
            "flutter": ["pubspec.yaml", "pubspec.lock"],
            "swift": ["Package.swift", "*.xcodeproj", "*.xcworkspace", "Podfile"],
            "kotlin": ["build.gradle.kts", "settings.gradle.kts"],
            "scala": ["build.sbt", "*.scala"],
            "elixir": ["mix.exs", "mix.lock"],
            "clojure": ["project.clj", "deps.edn", "build.boot"],
            "haskell": ["*.cabal", "stack.yaml", "cabal.project"],
            "r": ["DESCRIPTION", "*.Rproj", "renv.lock"],
            "julia": ["Project.toml", "Manifest.toml"],
            "dart": ["pubspec.yaml", "pubspec.lock"],
            "perl": ["Makefile.PL", "Build.PL", "cpanfile"],
            "c/c++": ["CMakeLists.txt", "Makefile", "*.vcxproj", "meson.build"],
            "mongodb": ["*.mongodb", "mongod.conf"],
            "postgres": ["*.sql", "postgresql.conf"],
            "redis": ["redis.conf", "*.rdb"],
            "nginx": ["nginx.conf", "*.nginx"],
            "apache": ["httpd.conf", ".htaccess"],
            "cmake": ["CMakeLists.txt", "*.cmake"],
            "make": ["Makefile", "GNUmakefile"],
            "ansible": ["ansible.cfg", "playbook.yml", "inventory.ini"],
            "jenkins": ["Jenkinsfile", "jenkins.yaml"],
            "gitlab-ci": [".gitlab-ci.yml"],
            "github-actions": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
            "circleci": [".circleci/config.yml"],
            "travis-ci": [".travis.yml"],
            "webpack": ["webpack.config.js", "webpack.config.ts"],
            "vite": ["vite.config.js", "vite.config.ts"],
            "rollup": ["rollup.config.js", "rollup.config.mjs"],
            "babel": [".babelrc", "babel.config.js", "babel.config.json"],
            "eslint": [".eslintrc", ".eslintrc.js", ".eslintrc.json", "eslint.config.js"],
            "prettier": [".prettierrc", "prettier.config.js"],
            "jest": ["jest.config.js", "jest.config.ts"],
            "pytest": ["pytest.ini", "pyproject.toml"],
            "maven": ["pom.xml"],
            "gradle": ["build.gradle", "build.gradle.kts", "settings.gradle"],
            "npm": ["package.json"],
            "pip": ["requirements.txt", "setup.py"],
            "conda": ["environment.yml", "conda.yml"],
            "poetry": ["pyproject.toml", "poetry.lock"]
        }
        
        # Language to framework mapping
        language_frameworks = {
            "Python": ["python", "django", "flask", "fastapi"],
            "JavaScript": ["nodejs", "javascript"],
            "TypeScript": ["typescript", "nodejs"],
            "Java": ["java", "spring"],
            "Go": ["go"],
            "Rust": ["rust"],
            "C#": ["dotnet", "csharp"],
            "C++": ["c/c++", "cpp"],
            "C": ["c/c++"],
            "Ruby": ["ruby", "rails"],
            "PHP": ["php", "laravel"],
            "Swift": ["swift", "ios"],
            "Kotlin": ["kotlin", "android"],
            "Scala": ["scala"],
            "Elixir": ["elixir", "phoenix"],
            "Clojure": ["clojure"],
            "Haskell": ["haskell"],
            "R": ["r"],
            "Julia": ["julia"],
            "Dart": ["dart", "flutter"],
            "Perl": ["perl"],
            "Objective-C": ["objective-c", "ios"],
            "Shell": ["shell", "bash"],
            "Vue": ["vue"],
            "HTML": ["html", "web"],
            "CSS": ["css", "web"],
            "SCSS": ["scss", "sass"],
            "Lua": ["lua"],
            "Groovy": ["groovy"],
            "PowerShell": ["powershell"]
        }
        
        try:
            languages_response = requests.get(languages_url, headers=headers)
            logger.info(f"Languages API response status: {languages_response.status_code}")
            if languages_response.status_code == 200:
                languages = languages_response.json()
                logger.info(f"Detected languages: {list(languages.keys())}")
                for language, _ in languages.items():
                    if language in language_frameworks:
                        tech_stack.extend(language_frameworks[language])
                        logger.info(f"Added frameworks for {language}: {language_frameworks[language]}")
            else:
                logger.error(f"Failed to fetch languages: {languages_response.status_code}")
                if languages_response.status_code == 404:
                    logger.error("Repository not found or no access (check if it's private and token is provided)")
        except Exception as e:
            logger.error(f"Error fetching languages: {e}")
        
        # Fetch root directory contents
        logger.info("Fetching root directory contents...")
        response = requests.get(api_url, headers=headers)
        logger.info(f"Contents API response status: {response.status_code}")
        if response.status_code != 200:
            logger.error(f"Failed to fetch contents: {response.status_code}")
            if response.status_code == 404:
                logger.error("Repository contents not found or no access (check if it's private and token is provided)")
            return tech_stack
        
        contents = response.json()
        files = [item['name'] for item in contents if item['type'] == 'file']
        dirs = [item['name'] for item in contents if item['type'] == 'dir']
        logger.info(f"Found {len(files)} files and {len(dirs)} directories")
        logger.info(f"Files: {files[:10]}...")  # Log first 10 files
        
        # Check for framework-specific patterns in package.json
        framework_detected = set()
        if "package.json" in files:
            logger.info("Checking package.json for frameworks...")
            try:
                pkg_url = f"https://api.github.com/repos/{owner}/{repo_name}/contents/package.json"
                pkg_response = requests.get(pkg_url, headers=headers)
                if pkg_response.status_code == 200:
                    import json
                    import base64
                    pkg_content = json.loads(base64.b64decode(pkg_response.json()['content']))
                    deps = {**pkg_content.get('dependencies', {}), **pkg_content.get('devDependencies', {})}
                    
                    if 'react' in deps or 'react-dom' in deps:
                        framework_detected.add('react')
                        logger.info("Detected React framework")
                    if 'vue' in deps or '@vue/cli' in deps:
                        framework_detected.add('vue')
                        logger.info("Detected Vue framework")
                    if '@angular/core' in deps:
                        framework_detected.add('angular')
                        logger.info("Detected Angular framework")
                    if 'next' in deps:
                        framework_detected.add('nextjs')
                        logger.info("Detected Next.js framework")
                    if 'nuxt' in deps:
                        framework_detected.add('nuxt')
                        logger.info("Detected Nuxt framework")
                    if 'svelte' in deps:
                        framework_detected.add('svelte')
                        logger.info("Detected Svelte framework")
                    if 'express' in deps:
                        framework_detected.add('express')
                        logger.info("Detected Express framework")
                    if 'nestjs' in deps or '@nestjs/core' in deps:
                        framework_detected.add('nestjs')
                        logger.info("Detected NestJS framework")
            except Exception as e:
                logger.error(f"Error checking package.json: {e}")
        
        # Check for Python framework indicators in requirements.txt or setup.py
        if "requirements.txt" in files or "setup.py" in files:
            logger.info("Checking Python files for frameworks...")
            try:
                file_to_check = "requirements.txt" if "requirements.txt" in files else "setup.py"
                req_url = f"https://api.github.com/repos/{owner}/{repo_name}/contents/{file_to_check}"
                req_response = requests.get(req_url, headers=headers)
                if req_response.status_code == 200:
                    import base64
                    req_content = base64.b64decode(req_response.json()['content']).decode('utf-8').lower()
                    
                    if 'django' in req_content:
                        framework_detected.add('django')
                        logger.info("Detected Django framework")
                    if 'flask' in req_content:
                        framework_detected.add('flask')
                        logger.info("Detected Flask framework")
                    if 'fastapi' in req_content:
                        framework_detected.add('fastapi')
                        logger.info("Detected FastAPI framework")
                    if 'tensorflow' in req_content or 'torch' in req_content:
                        framework_detected.add('ml/ai')
                        logger.info("Detected ML/AI framework")
            except Exception as e:
                logger.error(f"Error checking Python files: {e}")
        
        # Check for Ruby on Rails
        if "Gemfile" in files:
            try:
                gemfile_url = f"https://api.github.com/repos/{owner}/{repo_name}/contents/Gemfile"
                gemfile_response = requests.get(gemfile_url, headers=headers)
                if gemfile_response.status_code == 200:
                    import base64
                    gemfile_content = base64.b64decode(gemfile_response.json()['content']).decode('utf-8').lower()
                    
                    if 'rails' in gemfile_content:
                        framework_detected.add('rails')
            except:
                pass
        
        # Check for PHP frameworks
        if "composer.json" in files:
            try:
                composer_url = f"https://api.github.com/repos/{owner}/{repo_name}/contents/composer.json"
                composer_response = requests.get(composer_url, headers=headers)
                if composer_response.status_code == 200:
                    import json
                    import base64
                    composer_content = json.loads(base64.b64decode(composer_response.json()['content']))
                    deps = {**composer_content.get('require', {}), **composer_content.get('require-dev', {})}
                    
                    if any('laravel' in dep.lower() for dep in deps.keys()):
                        framework_detected.add('laravel')
                    if any('symfony' in dep.lower() for dep in deps.keys()):
                        framework_detected.add('symfony')
            except:
                pass
        
        # Check directories for CI/CD workflows
        if '.github' in dirs:
            try:
                workflows_url = f"https://api.github.com/repos/{owner}/{repo_name}/contents/.github/workflows"
                workflows_response = requests.get(workflows_url, headers=headers)
                if workflows_response.status_code == 200:
                    workflow_files = workflows_response.json()
                    if any(item['name'].endswith(('.yml', '.yaml')) for item in workflow_files):
                        framework_detected.add('github-actions')
            except:
                pass
        
        for tech, files_list in indicators.items():
            for file in files_list:
                if file in files or any(fnmatch.fnmatch(f, file) for f in files):
                    tech_stack.append(tech)
                    logger.info(f"Detected tech: {tech} from file: {file}")
                    break
        
        # Add detected frameworks
        tech_stack.extend(list(framework_detected))
        
        final_tech_stack = list(set(tech_stack))  # Remove duplicates
        logger.info(f"Final tech stack: {final_tech_stack}")
        return final_tech_stack
    
    except Exception as e:
        print(f"Error detecting tech stack: {e}")
        return tech_stack