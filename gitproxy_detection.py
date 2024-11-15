import os
import re
import json
import subprocess

# Pre-trained model patterns to detect in Python files
pretrained_models = ['ResNet', 'VGG', 'Inception', 'EfficientNet', 'BERT', 'GPT', 'T5', 'DistilBERT']

# Patterns for detecting external file downloads
download_patterns = ['wget', 'curl', 'requests.get', 'urllib.request.urlretrieve']

def get_git_diff():
    """Get a list of files changed in the latest commit."""
    result = subprocess.run(['git', 'diff', '--name-only', 'HEAD'], stdout=subprocess.PIPE, text=True)
    return result.stdout.strip().splitlines()

def detect_ml_imports(files):
    """Detects AI/ML library imports."""
    ml_issues = {}
    ml_libraries = ['torch', 'tensorflow', 'keras', 'sklearn', 'xgboost', 'catboost']
    
    for file_path in files:
        if file_path.endswith('.py'):
            with open(file_path, 'r') as file:
                content = file.readlines()
                
            for i, line in enumerate(content):
                if any(lib in line for lib in ml_libraries):
                    if file_path not in ml_issues:
                        ml_issues[file_path] = []
                    ml_issues[file_path].append(f"ML library detected on line {i+1}: {line.strip()}")
    
    return ml_issues

def detect_model_files(files):
    """Detects presence of ML model files like .h5, .pt, etc."""
    model_files = {}
    model_extensions = ['.h5', '.pt', '.pth', '.pb', '.joblib']
    
    for file_path in files:
        if any(file_path.endswith(ext) for ext in model_extensions):
            model_files[file_path] = "Model file detected"
    
    return model_files

def detect_weight_operations(files):
    """Detects code loading model weights."""
    weight_issues = {}
    weight_patterns = ['load_weights', 'torch.load', 'joblib.load', 'pickle.load']
    
    for file_path in files:
        if file_path.endswith('.py'):
            with open(file_path, 'r') as file:
                content = file.readlines()
                
            for i, line in enumerate(content):
                if any(pattern in line for pattern in weight_patterns):
                    if file_path not in weight_issues:
                        weight_issues[file_path] = []
                    weight_issues[file_path].append(f"Weight loading operation on line {i+1}: {line.strip()}")
    
    return weight_issues

def detect_pretrained_models(files):
    """Detects pre-trained model usage."""
    pretrained_issues = {}
    
    for file_path in files:
        if file_path.endswith('.py'):
            with open(file_path, 'r') as file:
                content = file.readlines()
                
            for i, line in enumerate(content):
                if any(model in line for model in pretrained_models):
                    if file_path not in pretrained_issues:
                        pretrained_issues[file_path] = []
                    pretrained_issues[file_path].append(f"Pre-trained model usage on line {i+1}: {line.strip()}")
    
    return pretrained_issues

def detect_external_downloads(files):
    """Detects external file downloads."""
    download_issues = {}
    
    for file_path in files:
        if file_path.endswith('.py'):
            with open(file_path, 'r') as file:
                content = file.readlines()
                
            for i, line in enumerate(content):
                if any(cmd in line for cmd in download_patterns):
                    if file_path not in download_issues:
                        download_issues[file_path] = []
                    download_issues[file_path].append(f"External download on line {i+1}: {line.strip()}")
    
    return download_issues

def generate_json_report(ml_issues, model_files, weight_issues, pretrained_issues, download_issues):
    """Generates JSON report of all issues found."""
    report = {
        "AI_ML_Library_Detections": ml_issues,
        "Model_File_Detections": model_files,
        "Weight_Operation_Detections": weight_issues,
        "Pretrained_Model_Detections": pretrained_issues,
        "External_Download_Detections": download_issues
    }
    
    with open("gitproxy_report.json", "w") as report_file:
        json.dump(report, report_file, indent=4)
    print("Report saved to gitproxy_report.json")

    return report

def main():
    changed_files = get_git_diff()
    ml_issues = detect_ml_imports(changed_files)
    model_files = detect_model_files(changed_files)
    weight_issues = detect_weight_operations(changed_files)
    pretrained_issues = detect_pretrained_models(changed_files)
    download_issues = detect_external_downloads(changed_files)
    
    # Generate JSON report for all issues found
    report = generate_json_report(ml_issues, model_files, weight_issues, pretrained_issues, download_issues)
    
    # Reject push if any high-risk issues are found
    if any([ml_issues, model_files, weight_issues, pretrained_issues, download_issues]):
        print("Push rejected due to detected security or compliance issues.")
        exit(1)
    else:
        print("No high-risk issues detected.")

if __name__ == "__main__":
    main()