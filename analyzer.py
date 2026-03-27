import os
import json
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from dotenv import load_dotenv

load_dotenv()

# --- ROBUST PATH HANDLING ---
# 1. Get the workspace root (where the report should be)
workspace = os.getenv("GITHUB_WORKSPACE", os.getcwd())

# 2. Get the report path from env, or default to the workspace root
REPORT_FILE = os.getenv("REPORT_PATH", os.path.join(workspace, "trivy-report.json"))

def parse_trivy_report(file_path):
    # Debugging info to see exactly where it's looking
    print(f"🔍 Checking for report at: {file_path}")
    
    if not os.path.exists(file_path):
        # List files in the current dir to help troubleshoot in the logs
        print(f"❌ File not found. Files in {os.path.dirname(file_path) or '.'}: {os.listdir(os.path.dirname(file_path) or '.')}")
        return []

    try:
        with open(file_path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print("❌ Error: Report file is not valid JSON.")
        return []

    vulnerabilities = []

    # Trivy JSON structure check
    results = data.get("Results", [])
    if not results:
        return []

    for result in results:
        for v in result.get("Vulnerabilities", []):
            vulnerabilities.append({
                "package": v.get("PkgName"),
                "severity": v.get("Severity"),
                "description": v.get("Description"),
                "fix_version": v.get("FixedVersion"),
                "file": result.get("Target")
            })

    return vulnerabilities

def analyze_vulnerabilities():
    vulns = parse_trivy_report(REPORT_FILE)

    if not vulns:
        return "✅ No vulnerabilities found or report missing. Good job!"

    # Filter for high-impact issues
    filtered = [v for v in vulns if v["severity"] in ["HIGH", "CRITICAL"]]
    
    if not filtered:
        return "✅ No HIGH or CRITICAL vulnerabilities found."

    template = """
You are a senior security engineer. 
Analyze the vulnerabilities below and provide a concise security report.

Vulnerabilities:
{vulns}

For each vulnerability:
- Explain the issue simply
- Mention severity
- Suggest exact fix (version upgrade or code change)
- Give short actionable recommendation

Output clean markdown.
"""

    prompt = PromptTemplate.from_template(template)

    # Note: Ensure the model name is correct for your tier (e.g., gemini-1.5-flash)
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash", 
        temperature=0,
        max_retries=3,
        google_api_key=os.getenv("GOOGLE_API_KEY")
    )

    response = llm.invoke(prompt.format(vulns=filtered))
    return response.content

if __name__ == "__main__":
    result = analyze_vulnerabilities()
    print(result)

    # Save output to the workspace so it can be uploaded as an artifact later
    output_path = os.path.join(workspace, "ai-output.txt")
    with open(output_path, "w") as f:
        f.write(result)
