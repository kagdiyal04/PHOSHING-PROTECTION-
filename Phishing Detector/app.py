from flask import Flask, render_template, request, redirect, url_for, send_file
from feature_extraction import (
    check_url_features, classify_url, extract_features_from_dataset,
    get_url_length, has_ssl, contains_suspicious_keywords,
    analyze_url, get_domain_age
)
import os
import pathlib

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULT_FOLDER'] = 'results'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html', result=None)

@app.route('/check', methods=['POST'])
def check_url():
    url = request.form.get('url')
    if url:
        features = {
            'URL': url,
            'URL Length': get_url_length(url),
            'Has SSL': has_ssl(url),
            'Contains Suspicious Keywords': contains_suspicious_keywords(url),
            'Pattern/Impersonation Result': analyze_url(url),
            'Domain Age (days)': get_domain_age(url),
        }
        classification = classify_url(url)
        return render_template('index.html', result=classification, checked_url=url, features=features)
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_csv():
    if 'csv_file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['csv_file']
    if file.filename == '':
        return redirect(url_for('index'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    extract_features_from_dataset(file_path)

    all_results = pathlib.Path(app.config['UPLOAD_FOLDER']) / 'enhanced_dataset.csv'
    legit_only = pathlib.Path(app.config['UPLOAD_FOLDER']) / 'legitimate_sites.csv'

    return render_template('index.html', download_all=all_results.name, download_legit=legit_only.name)

@app.route('/download/<filename>')
def download_file(filename):
    path = pathlib.Path(app.config['UPLOAD_FOLDER']) / filename
    return send_file(str(path), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
