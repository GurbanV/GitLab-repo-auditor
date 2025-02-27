import os
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
import json
import fnmatch
from dateutil import parser
from dotenv import load_dotenv


load_dotenv()  


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
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
    with open('dependency_files.json', 'r', encoding='utf-8') as f:
        dependency_files = json.load(f)
except FileNotFoundError:
    console.print("[red]Could not find 'dependency_files.json'. Please check the file and try again.[/red]")
    exit(1)
except json.JSONDecodeError as e:
    console.print(f"[red]Error reading 'dependency_files.json': {e}[/red]")
    exit(1)


def initialize_gitlab(url: str, token: str) -> gitlab.Gitlab:
    """
    Initialize and authenticate GitLab client.
    """
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
    if project.namespace['kind'] == 'group':
        group = gl.groups.get(project.namespace['id'])
        group_members = get_all_members(group.members_all)
        group_name = group.name
        group_full_path = group.full_path
    return project_members, group_members, group_name, group_full_path


def classify_members(members, source, group_name=None, group_full_path=None):
    owners, maintainers = [], []
    for member in members:
        display_source = f"{source} ({group_full_path})" if group_name and group_name != group_full_path else source
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
                for item in tree_items:
                    if item['type'] == 'blob' and fnmatch.fnmatch(item['path'], file_pattern):
                        file_url = f"{gitlab_url}/{project.path_with_namespace}/-/blob/{branch}/{quote(item['path'], safe='/')}"
                        return item['path'], file_url
            except gitlab.exceptions.GitlabGetError:
                continue
        return None, None

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(check_dependency, file_pattern): (lang, file_pattern)
            for lang, files in dependency_files.items()
            for file_pattern in files
        }
        for future in as_completed(futures):
            lang, _ = futures[future]
            file_path, file_url = future.result()
            if file_path and file_url:
                detected_dependencies.append((lang, file_path, file_url))
    return detected_dependencies


def check_ci_cd_config(project):
    checks = ['semgrep', 'gitleaks', 'trivy', 'syft']
    branch_checks = {check: [] for check in checks}
    checked_branches = set()

    def check_branch(branch_name):
        if branch_name in checked_branches:
            return {}
        checked_branches.add(branch_name)
        try:
            ci_file = project.files.get(file_path='.gitlab-ci.yml', ref=branch_name)
            ci_config = ci_file.decode().decode('utf-8')
            return {check: branch_name for check in checks if check in ci_config}
        except gitlab.exceptions.GitlabGetError:
            return {}

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(check_branch, branch.name): branch.name
            for branch in get_branch_list(project.id)
            if branch.name not in checked_branches
        }
        for future in as_completed(futures):
            for check, branch_name in future.result().items():
                branch_checks[check].append(branch_name)
    return branch_checks


def is_project_private(project):
    return project.visibility == 'private'


def check_license_file(project):
    license_files = ['LICENSE', 'LICENSE.md']
    main_branches = ['main', 'master', 'develop', 'dev', 'stage', 'prod', 'preprod']
    for file_name in license_files:
        if check_file_exists(project, file_name, main_branches):
            return True
    return False


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
                    if size and size > 100 * 1024 * 1024:  # Files larger than 100MB
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
    protected_branches = project.protectedbranches.list()
    issues = []
    for branch in protected_branches:
        if branch.allow_force_push:
            issues.append(f"Force push is allowed on branch {branch.name}")
        if not branch.merge_access_levels:
            issues.append(f"Merge access levels not set for branch {branch.name}")
    return issues


def get_ci_config(project):
    try:
        ci_file = project.files.get(file_path='.gitlab-ci.yml', ref=project.default_branch or 'main')
        ci_config = ci_file.decode().decode('utf-8')
        return ci_config
    except gitlab.exceptions.GitlabGetError:
        return ""


def check_linting_tools(project):
    linting_tools = ['eslint', 'pylint', 'flake8', 'rubocop']
    ci_config = get_ci_config(project)
    for tool in linting_tools:
        if tool in ci_config:
            return True
    return False


def check_code_coverage(project):
    ci_config = get_ci_config(project)
    coverage_keywords = ['coverage', 'codecov', 'coveralls']
    for keyword in coverage_keywords:
        if keyword in ci_config:
            return True
    return False


def check_project(project, exclude_checks):
    results = {
        "protected_branches": [],
        "owners": 0,
        "maintainers": 0,
        "all_members": [],
        "changelog_present": False,
        "readme_present": False,
        "license_present": False,
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
    }

    try:
        if 'protected_branches' not in exclude_checks:
            branches = get_branch_list(project.id)
            protected_branches = project.protectedbranches.list(all=True)
            results["protected_branches"] = [
                branch.name for branch in branches
                if any(protected_branch.name == branch.name for protected_branch in protected_branches)
            ]

        if 'check_owners/maintainers' not in exclude_checks:
            project_members, group_members, group_name, group_full_path = get_project_and_group_members(project)
            owners, maintainers = classify_members(project_members, 'direct')
            group_owners, group_maintainers = classify_members(group_members, 'group', group_name, group_full_path)
            owners.extend(group_owners)
            maintainers.extend(group_maintainers)
            results["owners"] = len(owners)
            results["maintainers"] = len(maintainers)
            results["all_members"] = owners + maintainers

        if 'changelog_readme' not in exclude_checks:
            main_branches = ['main', 'master', 'develop', 'dev', 'stage', 'prod', 'preprod']
            results["changelog_present"] = check_file_exists(project, 'CHANGELOG.md', main_branches)
            results["readme_present"] = check_file_exists(project, 'README.md', main_branches)
            results["license_present"] = check_license_file(project)

        if 'merge_requests_reviews' not in exclude_checks:
            mrs = project.mergerequests.list(state='merged', order_by='updated_at', per_page=100)
            total_mrs = len(mrs)
            reviewed_mrs = sum(1 for mr in mrs if mr.upvotes >= 2)
            results["merge_requests_reviews"] = (reviewed_mrs / total_mrs) * 100 if total_mrs > 0 else 0

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

    except gitlab.exceptions.GitlabGetError as e:
        console.print(f"[red]Access error to project '{project.name}': {e}[/red]")

    return results


def print_results(project, results, exclude_checks):
    console.print(f"\n[bold]Audit results for project '{project.name}':[/bold]")
    console.print("------------------------------------")

    if 'project_private' not in exclude_checks:
        visibility = 'Private' if results['project_private'] else 'Public'
        console.print(f"[bold]Project visibility:[/bold] {visibility}")
        if not results['project_private']:
            console.print("[red]❗ The project is public. It is recommended to set it to private if it contains confidential information.[/red]")
    console.print("------------------------------------")

    if 'protected_branches' not in exclude_checks:
        branches = ', '.join(results['protected_branches'])
        console.print(f"[bold]Protected branches:[/bold] {branches}" if branches else "[red]No protected branches found. It is recommended to protect the main branches of the project.[/red]")
    console.print("------------------------------------")

    if 'check_owners/maintainers' not in exclude_checks:
        table = Table(title="Owners and Maintainers", show_header=True)
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
            console.print("=> [red]Recommendation: Reduce the number of owners to 3 or fewer.[/red]")
        if results['maintainers'] > 5:
            console.print("=> [red]Recommendation: Reduce the number of maintainers to 5 or fewer.[/red]")
    console.print("------------------------------------")

    if 'changelog_readme' not in exclude_checks:
        console.print(f"\n[bold]Presence of CHANGELOG.md:[/bold] {'Yes ✅' if results['changelog_present'] else 'No ❗'}")
        if not results['changelog_present']:
            console.print("[red]CHANGELOG.md file is missing. It is recommended to add a changelog file to track the project's history.[/red]")
        console.print(f"[bold]Presence of README.md:[/bold] {'Yes ✅' if results['readme_present'] else 'No ❗'}")
        if not results['readme_present']:
            console.print("[red]README.md file is missing. It is recommended to add a project description.[/red]")
        console.print(f"[bold]Presence of LICENSE:[/bold] {'Yes ✅' if results['license_present'] else 'No ❗'}")
        if not results['license_present']:
            console.print("[red]LICENSE file is missing. It is recommended to specify the project's license.[/red]")
    console.print("------------------------------------")

    if 'merge_requests_reviews' not in exclude_checks:
        thumbs = '👍' if results['merge_requests_reviews'] >= 50 else '👎'
        console.print(f"\n[bold]Percentage of Merge Requests with >= 2 approvals:[/bold] {results['merge_requests_reviews']}% {thumbs}")
        if results['merge_requests_reviews'] < 50:
            console.print("[red]The last 50 MRs have no approvals. It is recommended to increase the number of reviews and approvals to improve code quality.[/red]")
    console.print("------------------------------------")

    if 'ci_cd_checks' not in exclude_checks:
        security_tools_descriptions = {
            "semgrep": "Semgrep (SAST code analysis)",
            "gitleaks": "Gitleaks (secret leaks detection)",
            "syft": "Syft (Software Bill of Materials - SBOM)",
            "trivy": "Trivy (vulnerability scanning)"
        }

        console.print("\n[bold]Checking for security actions in CI/CD Pipeline:[/bold]")
        for check in ["semgrep", "gitleaks", "syft", "trivy"]:
            branches = ', '.join(results['ci_cd_checks'].get(check, []))
            description = security_tools_descriptions.get(check, check.upper())
            if branches:
                console.print(f"- {description} is present in branches: {branches}")
            else:
                console.print(f"[red]- {description} is missing ❗ It is recommended to add {description} to enhance security.[/red]")
        console.print(f"\n[bold]Presence of linting tools in CI/CD:[/bold] {'Yes ✅' if results['linting_tools'] else 'No ❗'}")
        if not results['linting_tools']:
            console.print("[red]Linting tools are missing. It is recommended to add linters to maintain code quality. More info: [link=https://www.sonarsource.com/learn/linter/]Link to linter information[/link][/red]")
        console.print(f"[bold]Code coverage reports generation:[/bold] {'Yes ✅' if results['code_coverage'] else 'No ❗'}")
        if not results['code_coverage']:
            console.print("[red]Code coverage reports are not generated. More info: [link=https://docs.gitlab.com/ee/ci/testing/code_coverage.html]Link to code coverage information[/link][/red]")
    console.print("------------------------------------")

    if 'dependencies' not in exclude_checks:
        console.print("\n[bold]Checking for fixed dependencies:[/bold]")
        if results['dependencies']:
            current_language = None
            for lang, dep_file, file_url in results['dependencies']:
                if lang != current_language:
                    if current_language is not None:
                        console.print("\n")
                    current_language = lang
                    console.print(f"=> Language: {lang}")
                console.print(f"Dependency file: [link={file_url}]{dep_file}[/link]")
        else:
            console.print("[red]No dependency files found. It is recommended to add dependency files for package management.[/red]")
    console.print("------------------------------------")

    if 'branch_policies' not in exclude_checks:
        console.print("\n[bold]Branch protection policies:[/bold]")
        if results['branch_policy_issues']:
            for issue in results['branch_policy_issues']:
                console.print(f"[red]- {issue}[/red]")
        else:
            console.print("All branch policies are properly configured ✅")
    console.print("------------------------------------")

    if 'large_files' not in exclude_checks:
        console.print("\n[bold]Large files in the repository (over 100MB):[/bold]")
        if results['large_files']:
            for file_path, size in results['large_files']:
                size_mb = size / (1024 * 1024)
                console.print(f"[red]- {file_path}: {size_mb:.2f} MB[/red]")
            console.print("[red]It is recommended to remove or replace large files to optimize the repository.[/red]")
        else:
            console.print("No large files found ✅")
    console.print("------------------------------------")

    if 'repository_health' not in exclude_checks:
        last_activity = results['last_activity']
        if last_activity:
            last_activity_dt = parser.isoparse(last_activity)
            last_activity_dt_utc = last_activity_dt.astimezone(timezone.utc)
            now_utc = datetime.now(timezone.utc)
            days_since_last_activity = (now_utc - last_activity_dt_utc).days
            console.print(f"\n[bold]Last activity:[/bold] {last_activity_dt_utc.strftime('%Y-%m-%d %H:%M:%S %Z')} ({days_since_last_activity} days ago)")
        console.print(f"[bold]Open issues:[/bold] {results['open_issues']}")
        console.print(f"[bold]Open Merge Requests:[/bold] {results['open_merge_requests']}")


def generate_report(project, results):
    report_content = f"# Audit Report for Project '{project.name}'\n\n"
    report_content += "---\n\n"
    
    visibility = 'Private' if results['project_private'] else 'Public'
    report_content += f"**Project visibility:** {visibility}\n\n"

    report_content += "---\n\n"

    branches = ', '.join(results['protected_branches'])
    report_content += f"**Protected branches:** {branches if branches else 'None'}\n\n"

    report_content += "---\n\n"

    report_content += "## Owners and Maintainers\n\n"
    for member in results["all_members"]:
        name, username, role, source = member
        report_content += f"- {role}: {name} ({username}), Source: {source}\n"
    report_content += f"\n**Number of owners:** {results['owners']}\n"
    report_content += f"**Number of maintainers:** {results['maintainers']}\n\n"

    report_content += "---\n\n"

    report_content += f"**Presence of CHANGELOG.md:** {'Yes' if results['changelog_present'] else 'No'}\n"
    if not results['changelog_present']:
        report_content += "CHANGELOG.md file is missing. It is recommended to add a changelog file.\n"
    report_content += f"**Presence of README.md:** {'Yes' if results['readme_present'] else 'No'}\n"
    if not results['readme_present']:
        report_content += "README.md file is missing. It is recommended to add a project description.\n"
    report_content += f"**Presence of LICENSE:** {'Yes' if results['license_present'] else 'No'}\n"
    if not results['license_present']:
        report_content += "LICENSE file is missing. It is recommended to specify the project's license.\n\n"

    report_content += "---\n\n"

    report_content += f"**Percentage of Merge Requests with >= 2 approvals:** {results['merge_requests_reviews']}%\n"
    if results['merge_requests_reviews'] < 50:
        report_content += "It is recommended to increase the number of reviews and approvals to improve code quality.\n\n"
    else:
        report_content += "\n"

    report_content += "---\n\n"

    report_content += "## Checking for security actions in CI/CD Pipeline\n\n"
    security_tools_descriptions = {
        "semgrep": "Semgrep (SAST code analysis)",
        "gitleaks": "Gitleaks (secret leaks detection)",
        "syft": "Syft (Software Bill of Materials - SBOM)",
        "trivy": "Trivy (vulnerability scanning)"
    }
    for check in ["semgrep", "gitleaks", "syft", "trivy"]:
        branches = ', '.join(results['ci_cd_checks'].get(check, []))
        description = security_tools_descriptions.get(check, check.upper())
        if branches:
            report_content += f"- {description} is present in branches: {branches}\n"
        else:
            report_content += f"- {description} is missing. It is recommended to add {description} to enhance security.\n"
    report_content += f"\n**Presence of linting tools in CI/CD:** {'Yes' if results['linting_tools'] else 'No'}\n"
    if not results['linting_tools']:
        report_content += "Linting tools are missing. It is recommended to add linters to maintain code quality.\n"
    report_content += f"**Code coverage reports generation:** {'Yes' if results['code_coverage'] else 'No'}\n"
    if not results['code_coverage']:
        report_content += "Code coverage reports are not generated. It is recommended to set up code coverage.\n\n"

    report_content += "---\n\n"

    report_content += "## Checking for fixed dependencies\n\n"
    if results['dependencies']:
        current_language = None
        for lang, dep_file, file_url in results['dependencies']:
            if lang != current_language:
                current_language = lang
                report_content += f"### Language: {lang}\n"
            report_content += f"- Dependency file: [{dep_file}]({file_url})\n"
    else:
        report_content += "No dependency files found. It is recommended to add dependency files for package management.\n\n"

    report_content += "---\n\n"

    report_content += "## Branch protection policies\n\n"
    if results['branch_policy_issues']:
        for issue in results['branch_policy_issues']:
            report_content += f"- {issue}\n"
    else:
        report_content += "All branch policies are properly configured.\n\n"

    report_content += "---\n\n"

    report_content += "## Large files in the repository\n\n"
    if results['large_files']:
        for file_path, size in results['large_files']:
            size_mb = size / (1024 * 1024)
            report_content += f"- {file_path}: {size_mb:.2f} MB\n"
        report_content += "It is recommended to remove or replace large files to optimize the repository.\n\n"
    else:
        report_content += "No large files found.\n\n"

    report_content += "---\n\n"

    last_activity = results['last_activity']
    if last_activity:
        last_activity_dt = parser.isoparse(last_activity)
        last_activity_dt_utc = last_activity_dt.astimezone(timezone.utc)
        now_utc = datetime.now(timezone.utc)
        days_since_last_activity = (now_utc - last_activity_dt_utc).days
        report_content += f"**Last activity:** {last_activity_dt_utc.strftime('%Y-%m-%d %H:%M:%S %Z')} ({days_since_last_activity} days ago)\n"
    report_content += f"**Open issues:** {results['open_issues']}\n"
    report_content += f"**Open Merge Requests:** {results['open_merge_requests']}\n"

    report_filename = f"{project.name}_audit_report.md"
    with open(report_filename, "w", encoding='utf-8') as report_file:
        report_file.write(report_content)
    console.print(f"\n[bold]Audit report saved to {report_filename}[/bold]")


def main():
    global private_token, gitlab_url, gl
    parser = argparse.ArgumentParser(description='Audit GitLab projects for compliance with internal standards and best practices.')
    parser.add_argument('--exclude', nargs='+', help='Exclude specific checks (e.g., protected_branches, check_owners/maintainers, changelog_readme, merge_requests_reviews, ci_cd_checks, dependencies, project_private, branch_policies, large_files, repository_health)')
    parser.add_argument('--output', choices=['console', 'markdown'], default='console', help='Specify output format')
    parser.add_argument('--token', help='Specify GitLab private token')
    parser.add_argument('--url', help='Specify GitLab URL')
    args = parser.parse_args()

    private_token = args.token if args.token else os.getenv('GITLAB_PRIVATE_TOKEN')
    gitlab_url = args.url if args.url else os.getenv('GITLAB_URL')
    if not private_token or not gitlab_url:
        console.print("[red]Please set the GITLAB_PRIVATE_TOKEN and GITLAB_URL environment variables.[/red]")
        exit(1)
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
            project = futures[future]
            try:
                results = future.result()
                print_results(project, results, exclude_checks)
                if args.output == 'markdown':
                    generate_report(project, results)
            except Exception as e:
                console.print(f"[red]Error checking project '{project.name}': {e}[/red]")


if __name__ == "__main__":
    main()
