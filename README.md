# PHISHING-PROTECTION-
This project is a Flask-based web application that detects phishing websites using rule-based feature extraction. It allows users to input single URLs or upload a CSV file of multiple URLs for classification. The app includes CAPTCHA verification, a clean Bootstrap UI with a blue theme, and allows users to download a CSV containing only legitimate URLs after processing.

Features
CAPTCHA-protected user input to prevent bots

Analyze a single URL or upload a CSV of URLs

Rule-based detection using:

URL length

SSL certificate presence

Suspicious keyword check

Domain age from WHOIS lookup

Known phishing domain patterns

Filters and saves only legitimate URLs in the final CSV

Responsive and user-friendly frontend using Bootstrap

Technologies Used
Python 3.x

Flask

Pandas

Bootstrap 5

Whois library

HTML and CSS

Folder Structure
php
Copy
Edit
pblphishing_tools/
│
├── app.py                      # Main Flask application
├── requirements.txt           # Python dependencies
├── uploads/                   # Uploaded CSVs
├── processed/                 # Processed and filtered CSVs
├── templates/
│   └── index.html             # HTML template(frontend)
└── static/
    └── css/
        └── style.css          # Custom styling(frontend)
Installation and Running
Clone the repository:

bash
Copy
Edit
git clone :(https://github.com/kagdiyal04/PHISHING-PROTECTION-/blob/main/README.md
)
cd PHISHING-PROTECTION-
Install required packages:

bash
Copy
Edit
pip install -r requirements.txt
Start the Flask server:


bash

Copy

Edit

python app.py

Open your browser and visit:

http://127.0.0.1:5000/

CSV Format Example

csv

Copy

Edit

url

http://example.com

https://bank-login-update.com

http://secure-login.biz
Author


Ayush kumar


college project on cyber security concerns.

