from flask import Flask, render_template, request
import whois
from urllib.parse import urlparse
import re
from datetime import datetime

app = Flask(__name__)

history = []

def check_url(url):
    risk = "Low"
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc

    if not url.startswith("https"):
        risk = "High"
        reasons.append("No HTTPS")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        risk = "High"
        reasons.append("Using IP address")

    if "@" in url or "-" in domain:
        risk = "Medium"
        reasons.append("Suspicious characters")

    if domain.count(".") > 3:
        risk = "Medium"
        reasons.append("Too many subdomains")

    try:
        info = whois.whois(domain)
        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age = (datetime.now() - creation_date).days
            if age < 180:
                risk = "High"
                reasons.append("New domain")
    except:
        reasons.append("WHOIS not found")

    return risk, ", ".join(reasons)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    url = ""

    if request.method == "POST":
        url = request.form["url"]
        risk, reason = check_url(url)

        result = {
            "url": url,
            "risk": risk,
            "reason": reason
        }

        history.append(result)

    # Chart data
    high = len([x for x in history if x["risk"] == "High"])
    medium = len([x for x in history if x["risk"] == "Medium"])
    low = len([x for x in history if x["risk"] == "Low"])

    return render_template(
        "index.html",
        result=result,
        url=url,
        high=high,
        medium=medium,
        low=low
    )


if __name__ == "__main__":
    app.run(debug=True)