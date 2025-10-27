from flask import Flask, render_template, request, jsonify
import yara
import os
from pathlib import Path

app = Flask(__name__)

# Configuration
MALICIOUS_SAMPLES_DIR = './malicious_samples'
CLEAN_SAMPLES_DIR = './clean_samples'
FLAG = 'MINUTEMAN{w3_ju57_l0v3_y37_4n07h3r_r1d1cul0u5_rul3_0300393325}'

# Ensure directories exist
os.makedirs(MALICIOUS_SAMPLES_DIR, exist_ok=True)
os.makedirs(CLEAN_SAMPLES_DIR, exist_ok=True)

def get_files_from_directory(directory):
    """Get all files from a directory recursively"""
    files = []
    for root, dirs, filenames in os.walk(directory):
        for filename in filenames:
            files.append(os.path.join(root, filename))
    return files


def test_yara_rule(rule_text, test_files):
    """
    Test a YARA rule against a list of files.
    Returns a list of files that matched the rule.
    """
    try:
        # Compile the YARA rule
        rules = yara.compile(source=rule_text)
        
        matches = []
        for file_path in test_files:
            try:
                # Test the rule against each file
                result = rules.match(file_path)
                if result:  # If there are any matches
                    matches.append(file_path)
            except Exception as e:
                # Handle individual file errors (corrupted files, etc.)
                print(f"Error scanning {file_path}: {str(e)}")
                continue
        
        return matches, None
    
    except yara.SyntaxError as e:
        return None, f"YARA Syntax Error: {str(e)}"
    except Exception as e:
        return None, f"Error compiling rule: {str(e)}"


@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')


@app.route('/api/validate', methods=['POST'])
def validate_rule():
    """API endpoint to validate a YARA rule"""
    data = request.get_json()
    
    if not data or 'rule' not in data:
        return jsonify({
            'success': False,
            'message': 'No YARA rule provided',
            'type': 'error'
        }), 400
    
    yara_rule = data['rule']
    
    # Get all files
    malicious_files = get_files_from_directory(MALICIOUS_SAMPLES_DIR)
    clean_files = get_files_from_directory(CLEAN_SAMPLES_DIR)
    
    if not malicious_files:
        return jsonify({
            'success': False,
            'message': 'No malicious samples found in directory',
            'type': 'error'
        }), 500
    
    if not clean_files:
        return jsonify({
            'success': False,
            'message': 'No clean samples found in directory',
            'type': 'error'
        }), 500
    
    # Test against malicious samples
    malicious_matches, error = test_yara_rule(yara_rule, malicious_files)
    if error:
        return jsonify({
            'success': False,
            'message': error,
            'type': 'error'
        }), 400
    
    # Test against clean samples
    clean_matches, error = test_yara_rule(yara_rule, clean_files)
    if error:
        return jsonify({
            'success': False,
            'message': error,
            'type': 'error'
        }), 400
    
    # Calculate false negatives (malicious samples not detected)
    false_negatives = len(malicious_files) - len(malicious_matches)
    false_negative_files = [f for f in malicious_files if f not in malicious_matches]
    
    # Calculate false positives (clean samples incorrectly flagged)
    false_positives = len(clean_matches)
    false_positive_files = clean_matches
    
    # Check if rule is perfect
    if false_negatives == 0 and false_positives == 0:
        return jsonify({
            'success': True,
            'message': 'Perfect! Your YARA rule has 0 false positives and 0 false negatives!',
            'flag': FLAG,
            'type': 'success',
            'details': {
                'maliciousDetected': len(malicious_matches),
                'maliciousTotal': len(malicious_files),
                'cleanPassed': len(clean_files),
                'cleanTotal': len(clean_files)
            }
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Rule validation failed',
            'type': 'warning',
            'details': {
                'falseNegatives': false_negatives,
                'falsePositives': false_positives,
                # 'fnSamples': [os.path.basename(f) for f in false_negative_files[:5]],  # Show first 5
                # 'fpSamples': [os.path.basename(f) for f in false_positive_files[:5]],  # Show first 5
                'maliciousDetected': len(malicious_matches),
                'maliciousTotal': len(malicious_files),
                'cleanTotal': len(clean_files)
            }
        })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistics about the sample datasets"""
    malicious_files = get_files_from_directory(MALICIOUS_SAMPLES_DIR)
    clean_files = get_files_from_directory(CLEAN_SAMPLES_DIR)
    
    return jsonify({
        'malicious_count': len(malicious_files),
        'clean_count': len(clean_files)
    })


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=17364)