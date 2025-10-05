import requests
import base64
import yaml

# Set up variables
GITHUB_TOKEN = '<TOKEN>'  # Replace with your PAT
REPO_OWNER = ''  # Replace with repository owner
REPO_NAMES = ['']  # Replace with your repository names


headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

# Get list of workflow files from the repository
def get_workflow_files(repo_owner, repo_name):
    url = f'https://github.com/api/v3/repos/{repo_owner}/{repo_name}/actions/workflows'
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    workflows = response.json()
    return [workflow['path'] for workflow in workflows['workflows']]

# Get content of a file from the repository
def get_file_content(repo_owner, repo_name, file_path):
    url = f'https://github.com/api/v3/repos/{repo_owner}/{repo_name}/contents/{file_path}'
    response = requests.get(url, headers=headers)
    if response.status_code == 404:
        print(f"File {file_path} not found in {repo_name}. Skipping.")
        return None
    response.raise_for_status()
    file_content = response.json()
    return file_content['content']

# Decode the base64 content of the workflow file
def decode_base64_content(encoded_content):
    return base64.b64decode(encoded_content).decode('utf-8')

# Extract marketplace actions from the workflow content
def extract_marketplace_actions(workflow_content):
    workflow_yaml = yaml.safe_load(workflow_content)
    jobs = workflow_yaml.get('jobs', {})
    actions = set()
    for job in jobs.values():
        steps = job.get('steps', [])
        for step in steps:
            if 'uses' in step and '/' in step['uses']:
                action = step['uses']
                if 'dependabot' not in action:  # Ignore dependabot actions
                    actions.add(action)
    return actions

def process_repository(repo_owner, repo_name):
    workflow_files = get_workflow_files(repo_owner, repo_name)
    all_actions = set()
    for file_path in workflow_files:
        if not file_path.startswith('.github'):
            continue
        content = get_file_content(repo_owner, repo_name, file_path)
        if content is None:
            continue
        decoded_content = decode_base64_content(content)
        actions = extract_marketplace_actions(decoded_content)
        all_actions.update(actions)
    return all_actions

def main():
    all_repo_actions = {}
    for repo_name in REPO_NAMES:
        actions = process_repository(REPO_OWNER, repo_name)
        all_repo_actions[repo_name] = actions

    for repo_name, actions in all_repo_actions.items():
        print(f"Marketplace Actions used in the repository '{repo_name}':")
        for action in actions:
            print(action)
        print("\n")

if __name__ == '__main__':
    main()
