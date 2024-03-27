from flask import Flask, render_template, request
import requests
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Replace "YOUR_VIRUSTOTAL_API_KEY" with your actual VirusTotal API key
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

def get_final_url(url):
    try:
        response = requests.head(url, allow_redirects=True)
        return response.url
    except Exception as e:
        return f"Error: {e}"

def check_url(url):
    try:
        params = {'apikey': API_KEY, 'resource': url}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        json_response = response.json()
        if json_response['response_code'] == 1:
            if json_response['positives'] > 0:
                return "The url may be trying to lead you to a malicious website! - Flagged as malicious "
            else:
                return "The URL is not malicious."
        else:
            return "URL not found in VirusTotal database."
    except Exception as e:
        return f"Error: {e}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    text = request.form.get('text', '')
    if not text:
        return 'Please provide some text.'

    urls = re.findall(r'(https?://\S+)', text)
    if not urls:
        return 'No URLs found in the provided text.'

    analysis_results = []
    for url in urls:
        final_url = get_final_url(url)
        analysis_result = check_url(final_url)
        analysis_results.append((final_url, analysis_result))

    return render_template('results.html', results=analysis_results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
