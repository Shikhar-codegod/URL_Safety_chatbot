import streamlit as st
import requests
import json
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load API keys
load_dotenv()
VIRUSTOTAL_API = os.getenv("VIRUSTOTAL_API_KEY")
URLSCAN_API = os.getenv("URLSCAN_API_KEY")
GOOGLE_API = os.getenv("GOOGLE_API_KEY")

# Base URL for Ollama
OLLAMA_API = "http://localhost:11434/api/chat"

st.set_page_config(page_title="URL Safety Chatbot", page_icon="🔗", layout="centered")

st.title("🔗 URL Safety Chatbot")
st.write("Paste a link and I’ll analyze whether it’s real, safe, free to use, and more.")


def analyze_with_ollama(url, site_data):
    """Send analysis request to Ollama model"""
    prompt = f"""
Analyze the following website details and return a JSON response.

Website: {url}
Details: {json.dumps(site_data, indent=2)}

Respond ONLY in valid JSON with this structure:
{{
  "site_validity": "Real/Fake",
  "safety": "Safe/Unsafe",
  "pricing": "Free/Subscription/Unknown",
  "user_friendly_summary": "Explain in simple language for a non-technical person."
}}
"""

    try:
        response = requests.post(
            OLLAMA_API,
            json={
                "model": "llama3",
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            },
            timeout=60,
        )
        data = response.json()

        content = None
        if "message" in data and isinstance(data["message"], dict):
            content = data["message"].get("content")
        if not content and "response" in data:
            content = data["response"]
        if not content and "output" in data:
            content = data["output"]

        if not content:
            return {"user_friendly_summary": "⚠️ Unexpected Ollama response format."}

        # Extract JSON
        try:
            json_start = content.find("{")
            json_end = content.rfind("}") + 1
            if json_start != -1 and json_end != -1:
                return json.loads(content[json_start:json_end])
            else:
                return {"user_friendly_summary": content}
        except json.JSONDecodeError:
            return {"user_friendly_summary": content}  # fallback to plain text

    except Exception as e:
        return {"user_friendly_summary": f"Error calling Ollama: {str(e)}"}


def get_basic_site_info(url):
    """Collect some raw info about the URL (before sending to LLM)"""
    parsed = urlparse(url)
    domain = parsed.netloc

    site_data = {
        "domain": domain,
        "scheme": parsed.scheme,
        "path": parsed.path,
    }

    # Try to reach website
    try:
        r = requests.get(url, timeout=5)
        site_data["status_code"] = r.status_code
    except Exception as e:
        site_data["status"] = f"Unreachable ({str(e)})"

    return site_data


def check_with_virustotal(url):
    """Check URL with VirusTotal API"""
    if not VIRUSTOTAL_API:
        return {"virustotal": "API key missing"}
    try:
        headers = {"x-apikey": VIRUSTOTAL_API}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls", headers=headers)
        # VirusTotal requires URL submission first
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
        )
        analysis_id = resp.json()["data"]["id"]

        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
        )
        return {"virustotal": result.json()}
    except Exception as e:
        return {"virustotal": f"Error: {str(e)}"}


def check_with_urlscan(url):
    """Check URL with URLScan.io API"""
    if not URLSCAN_API:
        return {"urlscan": "API key missing"}
    try:
        headers = {"API-Key": URLSCAN_API, "Content-Type": "application/json"}
        data = {"url": url, "visibility": "public"}
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
        return {"urlscan": response.json()}
    except Exception as e:
        return {"urlscan": f"Error: {str(e)}"}


def check_with_google(url):
    """Check URL with Google Safe Browsing API"""
    if not GOOGLE_API:
        return {"google_safe_browsing": "API key missing"}
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API}"
        payload = {
            "client": {"clientId": "url-safety-bot", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = requests.post(endpoint, json=payload)
        result = response.json()
        if "matches" in result:
            return {"google_safe_browsing": "Unsafe"}
        else:
            return {"google_safe_browsing": "Safe"}
    except Exception as e:
        return {"google_safe_browsing": f"Error: {str(e)}"}


# Streamlit UI
url = st.text_input("Enter a website URL:")

if st.button("Check Website"):
    if url:
        st.info("🔍 Analyzing website, please wait...")

        site_data = get_basic_site_info(url)

        # Check with external APIs
        vt_result = check_with_virustotal(url)
        us_result = check_with_urlscan(url)
        gsb_result = check_with_google(url)

        # Merge all info before sending to Llama
        site_data.update(vt_result)
        site_data.update(us_result)
        site_data.update(gsb_result)

        # Analyze with Ollama
        analysis = analyze_with_ollama(url, site_data)

        st.subheader("📊 Analysis Results")

        if "site_validity" in analysis:
            st.write(f"**Validity:** {analysis['site_validity']}")
        if "safety" in analysis:
            st.write(f"**Safety:** {analysis['safety']}")
        if "pricing" in analysis:
            st.write(f"**Pricing:** {analysis['pricing']}")

        st.write("**Summary:**")
        st.success(analysis.get("user_friendly_summary", "No summary available."))

    else:
        st.warning("⚠️ Please enter a valid URL.")
