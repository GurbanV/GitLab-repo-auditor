import os
import sys
import logging
import gitlab
import warnings
import argparse
from urllib.parse import quote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
import fnmatch
from dateutil import parser
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
warnings.filterwarnings("ignore")

console = Console()

gl = None
private_token = None
gitlab_url = None

# Access levels
MAINTAINER_ACCESS = 40
OWNER_ACCESS = 50

# Load dependency_files from JSON file
dependency_files = {}
dependency_file_path = 'dependency_files.json'
try:
    with open(dependency_file_path, 'r', encoding='utf-8') as f:
        dependency_files = json.load(f)
except FileNotFoundError:
    console.print("[red]Could not find 'dependency_files.json'. Please check the file and try again.[/red]")
    sys.exit(1)
except json.JSONDecodeError as e:
    console.print(f"[red]Error reading 'dependency_files.json': {e}[/red]")
    sys.exit(1)


def initialize_gitlab(url: str, token: str) -> gitlab.Gitlab:
    """Initialize and authenticate GitLab client."""
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = "https://" + url
    try:
        gl_instance = gitlab.Gitlab(url, private_token=token, ssl_verify=False)
        gl_instance.auth()
        return gl_instance
    except gitlab.exceptions.GitlabAuthenticationError:
        console.print("[red]Authentication error. Please check your private token.[/red]")
        sys.exit(1)
    except gitlab.exceptions.GitlabConnectionError:
        console.print("[red]Failed to connect to GitLab. Please check the URL.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error during GitLab initialization: {e}[/red]")
        sys.exit(1)


@lru_cache(maxsize=128)
def get_all_members(manager):
    """Retrieve all members in batches."""
    members = []
    page = 1
    while True:
        batch = manager.list(page=page, per_page=100)
        if not batch:
            break
        members.extend(batch)
        page += 1
    return members


@lru_cache(maxsize=128)
def get_project_and_group_members(project):
    project_members = get_all_members(project.members)
    group_members, group_name, group_full_path = [], None, None
    if project.namespace.get('kind') == 'group':
        group = gl.groups.get(project.namespace['id'])
        group_members = get_all_members(group.members_all)
        group_name = group.name
        group_full_path = group.full_path
    return project_members, group_members, group_name, group_full_path


def classify_members(members, source, group_name=None, group_full_path=None):
    owners, maintainers = [], []
    for member in members:
        display_source = f"{source} ({group_full_path})" if group_name and group_name != group_full_path else source
        if hasattr(member, 'access_level'):
            if member.access_level == OWNER_ACCESS:
                owners.append((member.name, member.username, "Owner", display_source))
            elif member.access_level == MAINTAINER_ACCESS:
                maintainers.append((member.name, member.username, "Maintainer", display_source))
    return owners, maintainers


@lru_cache(maxsize=128)
def get_branch_list(project_id):
    return gl.projects.get(project_id).branches.list(all=True)


def check_file_exists(project, file_path, branches):
    for branch in branches:
        try:
            project.files.get(file_path=file_path, ref=branch)
            return True
        except gitlab.exceptions.GitlabGetError:
            continue
    return False


def check_fixed_dependencies(project):
    detected_dependencies = []
    main_branches = ['main', 'master', 'develop', 'dev', 'stage', 'preprod']

    def check_dependency(file_pattern):
        for branch in main_branches:
            try:
                tree_items = project.repository_tree(ref=branch, recursive=True)
                if not tree_items:
                    continue
                for item in tree_items:
                    if item['type'] == 'blob' and fnmatch.fnmatch(item['path'], file_pattern):
                        file_url = f"{gitlab_url}/{project.path_with_namespace}/-/blob/{branch}/{quote(item['path'], safe='/')}"
                        return item['path'], file_url
            except gitlab.exceptions.GitlabGetError:
                continue
        return None, None

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(check_dependency, fp): (lang, fp)
            for lang, files in dependency_files.items()
            for fp in files
        }
        for future in as_completed(futures):
            lang, _ = futures[future]
            file_path, file_url = future.result()
            if file_path and file_url:
                detected_dependencies.append((lang, file_path, file_url))
    return detected_dependencies


def check_ci_cd_config(project):
    """Checks for presence of semgrep, gitleaks, trivy, syft in .gitlab-ci.yml across all branches."""
    checks = ['semgrep', 'gitleaks', 'trivy', 'syft']
    branch_checks = {c: [] for c in checks}
    checked_branches = set()

    def check_branch(branch_name):
        if branch_name in checked_branches:
            return {}
        checked_branches.add(branch_name)
        try:
            ci_file = project.files.get(file_path='.gitlab-ci.yml', ref=branch_name)
            ci_config = ci_file.decode().decode('utf-8')
            found = {c: branch_name for c in checks if c in ci_config.lower()}
            return found
        except gitlab.exceptions.GitlabGetError:
            return {}

    branches = get_branch_list(project.id)
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_branch, b.name): b.name for b in branches}
        for future in as_completed(futures):
            result = future.result()
            for c, br in result.items():
                branch_checks[c].append(br)
    return branch_checks


def is_project_private(project):
    return project.visibility == 'private'


def check_for_large_files(project):
    large_files = []
    try:
        default_branch = project.default_branch or 'master'
        items = project.repository_tree(recursive=True, all=True, ref=default_branch)
        for item in items:
            if item['type'] == 'blob':
                try:
                    file = project.files.get(file_path=item['path'], ref=default_branch)
                    size = file.size
                    if size and size > 100 * 1024 * 1024:
                        large_files.append((item['path'], size))
                except gitlab.exceptions.GitlabGetError:
                    continue
    except gitlab.exceptions.GitlabGetError:
        pass
    return large_files


def get_open_issues_and_mrs(project):
    open_issues = project.issues.list(state='opened', all=True)
    open_mrs = project.mergerequests.list(state='opened', all=True)
    return len(open_issues), len(open_mrs)


def get_last_activity(project):
    return project.last_activity_at


def check_branch_policies(project):
    protected_branches = project.protectedbranches.list(all=True)
    issues = []
    for branch in protected_branches:
        if branch.allow_force_push:
            issues.append(f"Force push is allowed on branch {branch.name}")
        if not branch.merge_access_levels:
            issues.append(f"Merge access levels not set for branch {branch.name}")
    return issues


def get_ci_config(project):
    """Returns the content of .gitlab-ci.yml from the default branch (or main)."""
    try:
        default_branch = project.default_branch or 'main'
        ci_file = project.files.get(file_path='.gitlab-ci.yml', ref=default_branch)
        try:
            return ci_file.decode().decode('utf-8')
        except:
            return ci_file.decode('utf-8')
    except gitlab.exceptions.GitlabGetError:
        return ""


def check_linting_tools(project):
    linting_tools = ['eslint', 'pylint', 'flake8', 'rubocop']
    ci_config = get_ci_config(project).lower()
    for tool in linting_tools:
        if tool in ci_config:
            return True
    return False


def check_code_coverage(project):
    ci_config = get_ci_config(project).lower()
    for keyword in ['coverage', 'codecov', 'coveralls']:
        if keyword in ci_config:
            return True
    return False


def perform_additional_checks(project, owners_count):
    """
    Perform additional checks:
      - Protected Tags
      - MR Pipeline Requirement
      - CI/CD Variables Protection
      - Separate Caches for Protected Branches
      - Job Timeout
      - Approvals Before Merge
      - CODEOWNERS File
      - Self-Approval Restriction
      - User Reauthentication
      - CI/CD Variables Masked
      - Signed Commits
      - Push Rules
      - Project Owners Count
      - Protected Runners
      - Group Runners Usage
    """
    checks = {
        "protected_tags": [],
        "mr_pipeline_requirement": False,
        "ci_cd_variables_protection": False,
        "separate_caches_for_protected_branches": False,
        "job_timeout": None,
        "approvals_before_merge": 0,
        "codeowners_file": False,
        "self_approval_restriction": False,
        "user_reauthentication": False,
        "ci_cd_variables_masked": True,
        "signed_commits": False,
        "push_rules": False,
        "project_owners_count": owners_count,
        "protected_runners": False,
        "group_runners_usage": False
    }

    # 1) Protected Tags
    try:
        ptags = project.protectedtags.list(all=True)
        checks["protected_tags"] = [t.name for t in ptags]
    except:
        pass

    # 2) MR Pipeline Requirement
    try:
        if getattr(project, "only_allow_merge_if_pipeline_succeeds", False):
            checks["mr_pipeline_requirement"] = True
    except:
        pass

    # 3) CI/CD Variables Protection
    try:
        vars_ = project.variables.list(all=True)
        protected_vars = [v for v in vars_ if v.protected]
        checks["ci_cd_variables_protection"] = (len(protected_vars) == len(vars_)) if vars_ else True
    except:
        pass

    # 4) Separate Caches for Protected Branches
    ci_config = get_ci_config(project).lower()
    if "cache:" in ci_config and "only:" in ci_config and "protected" in ci_config:
        checks["separate_caches_for_protected_branches"] = True

    # 5) Job Timeout
    try:
        checks["job_timeout"] = getattr(project, "build_timeout", None)
    except:
        pass

    # 6) Approvals Before Merge
    try:
        if hasattr(project, "approvals_before_merge"):
            checks["approvals_before_merge"] = project.approvals_before_merge
    except:
        pass

    # 7) CODEOWNERS File
    main_branches = ['main', 'master', 'develop', 'dev', 'stage', 'prod', 'preprod']
    for possible_path in ["CODEOWNERS", ".gitlab/CODEOWNERS"]:
        if check_file_exists(project, possible_path, main_branches):
            checks["codeowners_file"] = True
            break

    # 8) Self-Approval Restriction
    try:
        if hasattr(project, "merge_requests_author_approval"):
            if project.merge_requests_author_approval is False:
                checks["self_approval_restriction"] = True
    except:
        pass

    # 9) User Reauthentication
    try:
        if hasattr(project, "require_password_to_approve") and project.require_password_to_approve:
            checks["user_reauthentication"] = True
    except:
        pass

    # 10) CI/CD Variables Masked
    try:
        vars_ = project.variables.list(all=True)
        for v in vars_:
            key_upper = v.key.upper()
            if ("TOKEN" in key_upper or "SECRET" in key_upper) and not v.masked:
                checks["ci_cd_variables_masked"] = False
                break
    except:
        checks["ci_cd_variables_masked"] = False

    # 11) Signed Commits
    try:
        push_rules = project.pushrules.get()
        if getattr(push_rules, "commit_committer_check", False):
            checks["signed_commits"] = True
    except:
        pass

    # 12) Push Rules
    try:
        pr = project.pushrules.get()
        if pr:
            checks["push_rules"] = True
    except:
        pass

    # 13) Project Owners Count is already provided

    # 14) Protected Runners
    try:
        all_runners = project.runners.list(all=True)
        checks["protected_runners"] = any(getattr(r, 'protected', False) for r in all_runners)
    except:
        pass

    # 15) Group Runners Usage
    try:
        all_runners = project.runners.list(all=True)
        checks["group_runners_usage"] = any(getattr(r, 'is_shared', False) for r in all_runners)
    except:
        pass

    return checks


def check_project(project, exclude_checks):
    results = {
        "protected_branches": [],
        "owners": 0,
        "maintainers": 0,
        "all_members": [],
        "changelog_present": False,
        "readme_present": False,
        "merge_requests_reviews": None,
        "ci_cd_checks": {},
        "dependencies": [],
        "project_private": True,
        "branch_policy_issues": [],
        "large_files": [],
        "open_issues": 0,
        "open_merge_requests": 0,
        "last_activity": None,
        "linting_tools": False,
        "code_coverage": False,
        "extra_checks": {}
    }

    try:
        if 'protected_branches' not in exclude_checks:
            branches = get_branch_list(project.id)
            prot_branches = project.protectedbranches.list(all=True)
            results["protected_branches"] = [
                branch.name for branch in branches
                if any(pb.name == branch.name for pb in prot_branches)
            ]

        if 'check_owners/maintainers' not in exclude_checks:
            pm, gm, gname, gfull = get_project_and_group_members(project)
            owners, maintainers = classify_members(pm, 'direct')
            gowners, gmaintainers = classify_members(gm, 'group', gname, gfull)
            owners.extend(gowners)
            maintainers.extend(gmaintainers)
            results["owners"] = len(owners)
            results["maintainers"] = len(maintainers)
            results["all_members"] = owners + maintainers

        if 'changelog_readme' not in exclude_checks:
            main_branches = ['main', 'master', 'develop', 'dev', 'stage', 'prod', 'preprod']
            results["changelog_present"] = check_file_exists(project, 'CHANGELOG.md', main_branches)
            results["readme_present"] = check_file_exists(project, 'README.md', main_branches)

        if 'merge_requests_reviews' not in exclude_checks:
            try:
                mrs = project.mergerequests.list(state='merged', order_by='updated_at', per_page=100)
                total = len(mrs)
                reviewed = sum(1 for mr in mrs if getattr(mr, 'upvotes', 0) >= 2)
                results["merge_requests_reviews"] = (reviewed / total) * 100 if total > 0 else 0
            except:
                results["merge_requests_reviews"] = 0

        if 'ci_cd_checks' not in exclude_checks:
            results["ci_cd_checks"] = check_ci_cd_config(project)
            results["linting_tools"] = check_linting_tools(project)
            results["code_coverage"] = check_code_coverage(project)

        if 'dependencies' not in exclude_checks:
            results["dependencies"] = check_fixed_dependencies(project)

        if 'project_private' not in exclude_checks:
            results["project_private"] = is_project_private(project)

        if 'branch_policies' not in exclude_checks:
            results["branch_policy_issues"] = check_branch_policies(project)

        if 'large_files' not in exclude_checks:
            results["large_files"] = check_for_large_files(project)

        if 'repository_health' not in exclude_checks:
            issues, mrs = get_open_issues_and_mrs(project)
            results["open_issues"] = issues
            results["open_merge_requests"] = mrs
            results["last_activity"] = get_last_activity(project)

        owners_count = results["owners"]
        results["extra_checks"] = perform_additional_checks(project, owners_count)

    except gitlab.exceptions.GitlabGetError as e:
        console.print(f"[red]Access error to project '{project.name}': {e}[/red]")
    except Exception as e:
        logger.error(f"Unexpected error in check_project for {project.name}: {e}")

    return results


def print_results(project, results, exclude_checks):
    console.print(f"\n[bold]Audit results for project '{project.name}':[/bold]")
    console.print("------------------------------------")

    visibility = 'Private' if results['project_private'] else 'Public'
    console.print(f"[bold]Project visibility:[/bold] {visibility}")
    if not results['project_private']:
        console.print("[red]❗ The project is public. It is recommended to set it to private if it contains confidential information.[/red]")
    console.print("------------------------------------")

    branches = ', '.join(results['protected_branches'])
    console.print(f"[bold]Protected branches:[/bold] {branches}" if branches else "[red]No protected branches found. Protect the main branches.[/red]")
    console.print("------------------------------------")

    table = Table(title="Owners and Maintainers", show_header=True, header_style="cyan")
    table.add_column("Name")
    table.add_column("Username")
    table.add_column("Role")
    table.add_column("Source")
    for member in results["all_members"]:
        name, username, role, source = member
        table.add_row(name, username, role, source)
    console.print(table)
    console.print(f"[bold]Number of owners:[/bold] {results['owners']}")
    console.print(f"[bold]Number of maintainers:[/bold] {results['maintainers']}")
    if results['owners'] > 3:
        console.print("[red]Recommendation: Reduce owners to 3 or fewer.[/red]")
    if results['maintainers'] > 5:
        console.print("[red]Recommendation: Reduce maintainers to 5 or fewer.[/red]")
    console.print("------------------------------------")

    console.print(f"\n[bold]Presence of CHANGELOG.md:[/bold] {'Yes ✅' if results['changelog_present'] else 'No ❗'}")
    console.print(f"[bold]Presence of README.md:[/bold] {'Yes ✅' if results['readme_present'] else 'No ❗'}")
    console.print("------------------------------------")

    thumbs = '👍' if (results['merge_requests_reviews'] or 0) >= 50 else '👎'
    console.print(f"\n[bold]Merge Requests with >= 2 approvals:[/bold] {results['merge_requests_reviews']}% {thumbs}")
    if (results['merge_requests_reviews'] or 0) < 50:
        console.print("[red]Increase MR approvals to improve code quality.[/red]")
    console.print("------------------------------------")

    security_tools_descriptions = {
        "semgrep": "Semgrep (SAST)",
        "gitleaks": "Gitleaks (Secret leaks)",
        "syft": "Syft (SBOM)",
        "trivy": "Trivy (Vulnerability scanning)"
    }
    console.print("\n[bold]CI/CD Pipeline Security Checks:[/bold]")
    for check in ["semgrep", "gitleaks", "syft", "trivy"]:
        branches = ', '.join(results['ci_cd_checks'].get(check, []))
        description = security_tools_descriptions.get(check, check.upper())
        if branches:
            console.print(f"- {description} found in branches: {branches}")
        else:
            console.print(f"[red]- {description} is missing ❗[/red]")
    console.print(f"\n[bold]Linting tools in CI/CD:[/bold] {'Yes ✅' if results['linting_tools'] else 'No ❗'}")
    console.print(f"[bold]Code coverage reports:[/bold] {'Yes ✅' if results['code_coverage'] else 'No ❗'}")
    console.print("------------------------------------")

    console.print("\n[bold]Fixed Dependencies:[/bold]")
    if results['dependencies']:
        current_language = None
        for lang, dep_file, file_url in results['dependencies']:
            if lang != current_language:
                current_language = lang
                console.print(f"=> Language: {lang}")
            console.print(f"Dependency file: [link={file_url}]{dep_file}[/link]")
    else:
        console.print("[red]No dependency files found.[/red]")
    console.print("------------------------------------")

    console.print("\n[bold]Branch Protection Policies:[/bold]")
    if results['branch_policy_issues']:
        for issue in results['branch_policy_issues']:
            console.print(f"[red]- {issue}[/red]")
    else:
        console.print("All branch policies are properly configured ✅")
    console.print("------------------------------------")

    console.print("\n[bold]Large Files (over 100MB):[/bold]")
    if results['large_files']:
        for file_path, size in results['large_files']:
            size_mb = size / (1024 * 1024)
            console.print(f"[red]- {file_path}: {size_mb:.2f} MB[/red]")
        console.print("[red]Remove or replace large files for optimization.[/red]")
    else:
        console.print("No large files found ✅")
    console.print("------------------------------------")

    console.print("\n[bold]Repository Health:[/bold]")
    last_activity = results['last_activity']
    if last_activity:
        last_activity_dt = parser.isoparse(last_activity)
        last_activity_dt_utc = last_activity_dt.astimezone(timezone.utc)
        now_utc = datetime.now(timezone.utc)
        days_since = (now_utc - last_activity_dt_utc).days
        console.print(f"Last activity: {last_activity_dt_utc.strftime('%Y-%m-%d %H:%M:%S %Z')} ({days_since} days ago)")
    console.print(f"Open issues: {results['open_issues']}")
    console.print(f"Open Merge Requests: {results['open_merge_requests']}")
    console.print("------------------------------------")

    extra = results.get("extra_checks", {})
    if extra:
        console.print("\n[bold]Additional Checks:[/bold]")
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Check")
        table.add_column("Status")
        for key, value in extra.items():
            status = "[green]Pass[/green]" if value else "[red]Fail[/red]"
            table.add_row(key.replace("_", " ").title(), status)
        console.print(table)
        recommendations = {
            "mr_pipeline_requirement": "Enable 'Only allow merge if pipeline succeeds' in project settings.",
            "ci_cd_variables_protection": "Ensure all CI/CD variables are marked as protected.",
            "separate_caches_for_protected_branches": "Configure caches in .gitlab-ci.yml with 'only: [protected]'.",
            "job_timeout": "Set a reasonable job timeout (e.g., 30 minutes).",
            "approvals_before_merge": "Set minimum approvals (e.g., 2) in your project settings.",
            "codeowners_file": "Add a CODEOWNERS file to define code review responsibilities.",
            "self_approval_restriction": "Disable self-approval in merge request settings.",
            "user_reauthentication": "Enable user reauthentication before approvals.",
            "ci_cd_variables_masked": "Mask all sensitive CI/CD variables.",
            "signed_commits": "Enforce signed commits through push rules.",
            "push_rules": "Configure push rules to restrict unauthorized changes.",
            "protected_runners": "Use protected runners for production pipelines.",
            "group_runners_usage": "Avoid using group/shared runners for sensitive projects."
        }
        failed = [key for key, value in extra.items() if not value]
        if failed:
            rec_lines = ["[bold red]Recommendations:[/bold red]"]
            for key in failed:
                rec = recommendations.get(key, "Please review your settings.")
                rec_lines.append(f"- {key.replace('_', ' ').title()}: {rec}")
            rec_panel = Panel("\n".join(rec_lines), title="Fix Your Settings", style="red")
            console.print(rec_panel)


def generate_report(project, results):
    report_lines = []
    report_lines.append(f"# Audit Report for Project '{project.name}'\n")
    
    # Project Visibility
    visibility = 'Private' if results['project_private'] else 'Public'
    report_lines.append(f"**Project visibility:** {visibility}\n")
    
    # Protected Branches
    branches = ', '.join(results['protected_branches']) or "None"
    report_lines.append(f"**Protected branches:** {branches}\n")
    
    # Owners and Maintainers
    report_lines.append("## Owners and Maintainers\n")
    for member in results["all_members"]:
        name, username, role, source = member
        report_lines.append(f"- **{role}**: {name} ({username}), Source: {source}")
    report_lines.append(f"\n**Number of owners:** {results['owners']}")
    report_lines.append(f"**Number of maintainers:** {results['maintainers']}\n")
    
    # Documentation (without LICENSE)
    report_lines.append("## Documentation Files\n")
    report_lines.append(f"**Presence of CHANGELOG.md:** {'Yes' if results['changelog_present'] else 'No'}")
    report_lines.append(f"**Presence of README.md:** {'Yes' if results['readme_present'] else 'No'}\n")
    
    # Merge Requests Reviews
    report_lines.append(f"**Percentage of Merge Requests with >= 2 approvals:** {results['merge_requests_reviews']}%\n")
    
    # CI/CD Checks
    report_lines.append("## CI/CD Checks\n")
    sec_tools = {
        "semgrep": "Semgrep (SAST code analysis)",
        "gitleaks": "Gitleaks (secret leaks detection)",
        "syft": "Syft (SBOM)",
        "trivy": "Trivy (vulnerability scanning)"
    }
    for tool, desc in sec_tools.items():
        branch_list = results['ci_cd_checks'].get(tool, [])
        if branch_list:
            report_lines.append(f"- {desc} is present in branches: {', '.join(branch_list)}")
        else:
            report_lines.append(f"- {desc} is **missing**")
    report_lines.append(f"\n**Linting tools in CI/CD:** {'Yes' if results['linting_tools'] else 'No'}")
    report_lines.append(f"**Code coverage reports:** {'Yes' if results['code_coverage'] else 'No'}\n")
    
    # Fixed Dependencies
    report_lines.append("## Fixed Dependencies\n")
    if results['dependencies']:
        current_language = None
        for lang, dep_file, file_url in results['dependencies']:
            if lang != current_language:
                current_language = lang
                report_lines.append(f"### Language: {lang}")
            report_lines.append(f"- Dependency file: [{dep_file}]({file_url})")
    else:
        report_lines.append("No dependency files found.\n")
    
    # Branch Protection Policies
    report_lines.append("## Branch Protection Policies\n")
    if results['branch_policy_issues']:
        for issue in results['branch_policy_issues']:
            report_lines.append(f"- {issue}")
    else:
        report_lines.append("All branch policies are properly configured.\n")
    
    # Large Files
    report_lines.append("## Large Files\n")
    if results['large_files']:
        for file_path, size in results['large_files']:
            size_mb = size / (1024 * 1024)
            report_lines.append(f"- {file_path}: {size_mb:.2f} MB")
    else:
        report_lines.append("No large files found.\n")
    
    # Repository Health
    report_lines.append("## Repository Health\n")
    last_activity = results['last_activity']
    if last_activity:
        last_activity_dt = parser.isoparse(last_activity)
        last_activity_dt_utc = last_activity_dt.astimezone(timezone.utc)
        now_utc = datetime.now(timezone.utc)
        days_since = (now_utc - last_activity_dt_utc).days
        report_lines.append(f"**Last activity:** {last_activity_dt_utc.strftime('%Y-%m-%d %H:%M:%S %Z')} ({days_since} days ago)")
    report_lines.append(f"**Open issues:** {results['open_issues']}")
    report_lines.append(f"**Open Merge Requests:** {results['open_merge_requests']}\n")
    
    # Additional Checks
    extra = results.get("extra_checks", {})
    if extra:
        report_lines.append("---\n")
        report_lines.append("## Additional Checks\n")
        table_lines = ["| Check | Status |", "| --- | --- |"]
        for key, value in extra.items():
            status = "Pass" if value else "Fail"
            # Mark Fail in red (using HTML tags in Markdown if supported)
            if not value:
                status = "<span style='color:red;'>Fail</span>"
            else:
                status = "<span style='color:green;'>Pass</span>"
            table_lines.append(f"| {key.replace('_', ' ').title()} | {status} |")
        report_lines.extend(table_lines)
        
        # Recommendations for failed checks
        recommendations = {
            "mr_pipeline_requirement": "Enable 'Only allow merge if pipeline succeeds' in project settings.",
            "ci_cd_variables_protection": "Ensure all CI/CD variables are marked as protected.",
            "separate_caches_for_protected_branches": "Configure caches in .gitlab-ci.yml with 'only: [protected]'.",
            "job_timeout": "Set a reasonable job timeout (e.g., 30 minutes).",
            "approvals_before_merge": "Set minimum approvals (e.g., 2) in your project settings.",
            "codeowners_file": "Add a CODEOWNERS file to define code review responsibilities.",
            "self_approval_restriction": "Disable self-approval in merge request settings.",
            "user_reauthentication": "Enable user reauthentication before approvals.",
            "ci_cd_variables_masked": "Mask all sensitive CI/CD variables.",
            "signed_commits": "Enforce signed commits via push rules.",
            "push_rules": "Configure push rules to restrict unauthorized changes.",
            "protected_runners": "Use protected runners for production pipelines.",
            "group_runners_usage": "Avoid using group/shared runners for sensitive projects."
        }
        failed = [key for key, value in extra.items() if not value]
        if failed:
            report_lines.append("\n**Recommendations for failed checks:**")
            for key in failed:
                rec = recommendations.get(key, "Review the settings.")
                report_lines.append(f"- **{key.replace('_', ' ').title()}**: {rec}")
    
    report_content = "\n".join(report_lines)
    report_filename = f"{project.name}_audit_report.md"
    with open(report_filename, "w", encoding="utf-8") as report_file:
        report_file.write(report_content)
    console.print(Panel.fit(f"Audit report saved to [bold]{report_filename}[/bold]", title="Report Generated", style="bold green"))


def main():
    global private_token, gitlab_url, gl
    parser = argparse.ArgumentParser(
        description='Audit GitLab projects for compliance with internal standards and best practices.'
    )
    parser.add_argument('--exclude', nargs='+', help='Exclude specific checks')
    parser.add_argument('--output', choices=['console', 'markdown'], default='console', help='Specify output format')
    parser.add_argument('--token', help='Specify GitLab private token')
    parser.add_argument('--url', help='Specify GitLab URL')
    args = parser.parse_args()

    private_token = args.token if args.token else os.getenv('GITLAB_PRIVATE_TOKEN')
    gitlab_url = args.url if args.url else os.getenv('GITLAB_URL')
    if not private_token or not gitlab_url:
        console.print("[red]Please set the GITLAB_PRIVATE_TOKEN and GITLAB_URL environment variables.[/red]")
        sys.exit(1)
    gl = initialize_gitlab(gitlab_url, private_token)

    exclude_checks = args.exclude if args.exclude else []
    project_ids = input("Enter one or more project IDs or URLs (comma-separated): ").split(',')

    projects = []
    for pid in project_ids:
        pid = pid.strip()
        if pid:
            try:
                if pid.isdigit():
                    projects.append(gl.projects.get(pid))
                else:
                    project_path = urlparse(pid).path.strip('/')
                    if project_path.endswith('.git'):
                        project_path = project_path[:-4]
                    project = gl.projects.get(project_path)
                    projects.append(project)
            except gitlab.exceptions.GitlabGetError as e:
                console.print(f"[red]Access error to project {pid}: {e}[/red]")
    for project in projects:
        console.print(f"[bold]Auditing project '{project.name}'...[/bold]")

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_project, project, exclude_checks): project for project in projects}
        for future in as_completed(futures):
            prj = futures[future]
            try:
                results = future.result()
                # Print results in console
                print_results(prj, results, exclude_checks)
                if args.output == 'markdown':
                    generate_report(prj, results)
            except Exception as e:
                console.print(f"[red]Error checking project '{prj.name}': {e}[/red]")


if __name__ == "__main__":
    main()
