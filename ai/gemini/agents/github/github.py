import requests
import os
from dotenv import load_dotenv
from langchain_core.documents import Document

load_dotenv()

github_token = os.getenv("GITHUB_TOKEN")

def fetch_github(owner, repo, endpoint):
    url = f"https://api.github.com/repos/{owner}/{repo}/{endpoint}"
    headers = {"Authorization": f"Bearer {github_token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
    return data

def load_issues(issues):
    docs = []
    for entry in issues:
        metadata = {
            "author": entry["user"]["login"],
            "comments": entry["comments"],
            "labels": entry["labels"],
            "created_at": entry["created_at"],
            "body": entry["body"],
        }
        data = entry["title"]
        if entry["body"]:
            data += entry["body"]
        docs.append(Document(page_content=data, metadata=metadata))
    return docs   

def fetch_github_issues(owner, repo):
    issues = fetch_github(owner, repo, "issues")
    docs = load_issues(issues)
    return docs



