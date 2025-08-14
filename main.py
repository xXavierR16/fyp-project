# create "app.py" using FLASK
from flask import Flask, render_template, request
import joblib
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.preprocessing import LabelEncoder
import validators

app = Flask(__name__)

# Global variables for model components
pipeline = None
file_ext_encoder = None

try:
    # Load the pipeline
    pipeline = joblib.load('pipeline_v2.pkl')
    print("Pipeline loaded successfully!")
    print(f"Pipeline steps: {[step[0] for step in pipeline.steps]}")

    # Try to load separate file extension encoder if it exists
    try:
        file_ext_encoder = joblib.load('file_ext_encoder2.pkl')
        print("File extension encoder loaded!")
    except:
        print("No separate file extension encoder found, will create one...")
        # Create a basic encoder with common extensions
        file_ext_encoder = LabelEncoder()
        # Common extensions from typical training data
        common_extensions = ['none', 'com', 'html', 'php', 'exe', 'dll', 'asp', 'jsp', 'htm']
        file_ext_encoder.fit(common_extensions)

except Exception as e:
    print(f"Error loading pipeline: {str(e)}")
    pipeline = None

# Match exact Colab feature extraction
SUSPICIOUS_KEYWORDS = ['encrypt', 'decrypt', 'pay', 'bitcoin', 'wallet']

def extract_features(url):
    try:
        url = str(url).strip().lower()
        parsed = urlparse(url)
        path = parsed.path

        # Extract file extension from path
        file_ext = path.split('.')[-1] if '.' in path else 'none'

        # Create features dictionary
        features = {
            'url': url,
            'url_length': len(url),
            'num_dots': url.count('.'),
            'is_https': int(url.startswith('https')),
            'has_ip': int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),
            'suspicious_keywords': sum(kw in url for kw in SUSPICIOUS_KEYWORDS),
            'exe_or_dll': int(any(x in path for x in ['.exe', '.dll'])),
            'has_dotcom': int('.com' in parsed.netloc),
            'file_ext': file_ext,
        }

        # 1: 6 numerical features (without file_ext_encoded)
        numerical_features_6 = [
            features['url_length'],
            features['num_dots'], 
            features['is_https'],
            features['has_ip'],
            features['suspicious_keywords'],
            features['exe_or_dll'],
            features['has_dotcom']
        ]

        # 2: 7 features (with file_ext_encoded)
        # Encode file extension
        file_ext_encoded = 0
        if file_ext_encoder:
            try:
                file_ext_encoded = file_ext_encoder.transform([file_ext])[0]
            except ValueError:
                print(f"Unknown file extension: {file_ext}, using 'none'")
                file_ext_encoded = file_ext_encoder.transform(['none'])[0]

        numerical_features_7 = numerical_features_6 + [file_ext_encoded]

        print(f"URL: {url}")
        print(f"File extension: {file_ext} (encoded: {file_ext_encoded})")
        print(f"6 features: {numerical_features_6}")
        print(f"7 features: {numerical_features_7}")

        return np.array(numerical_features_7)

    except Exception as e:
        print(f"Feature extraction error: {str(e)}")
        # Return default values that match expected feature count
        return np.array([0, 0, 0, 0, 0, 0, 0])

@app.route('/', methods=['GET', 'POST'])
def index():
    prediction = "System initializing..."

    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        if not url:
            prediction = "Please enter a URL"
        elif not validators.url(url):
            prediction = "Invalid URL format. Please enter a valid URL."
        else:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            try:
                if pipeline:
                    features = extract_features(url)
                    print(f"Final features shape: {features.shape}")
                    print(f"Final features: {features}")

                    # Make prediction using the pipeline
                    features_reshaped = features.reshape(1, -1)
                    pred = pipeline.predict(features_reshaped)[0]
                    print(f"Raw prediction: {pred}")

                    # Get prediction probability for confidence
                    try:
                        proba = pipeline.predict_proba(features_reshaped)[0]
                        print(f"Prediction probabilities: {proba}")
                        confidence = max(proba) * 100

                        # Determine result based on prediction (0=benign, 1=malicious)
                        if pred == 1:
                            result = "🚨 RANSOMWARE DETECTED"
                            risk_level = "HIGH RISK"
                        else:
                            result = "✅ BENIGN URL" 
                            risk_level = "SAFE"

                        prediction = f"{result} - {risk_level} (Confidence: {confidence:.1f}%)"

                    except Exception as prob_error:
                        print(f"Probability error: {prob_error}")
                        # Fallback without probability
                        if pred == 1:
                            prediction = "🚨 RANSOMWARE DETECTED - HIGH RISK"
                        else:
                            prediction = "✅ BENIGN URL - SAFE"
                else:
                    prediction = "❌ Model not loaded - Please check your .pkl file"

            except Exception as e:
                print(f"Prediction error: {str(e)}")
                prediction = f"❌ Error: {str(e)}"

    return render_template('index.html', prediction=prediction)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=81, debug=True)
