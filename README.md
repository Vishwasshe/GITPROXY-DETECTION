# GitProxy AI/ML Detection and Compliance Checker

This project is a customizable Git pre-push hook script designed for Citi Finos hackathon submissions. It detects AI/ML components, pre-trained models, external downloads, and high-risk operations in code changes, ensuring compliance and security.

## Features
- **AI/ML Library Detection**: Identifies common AI/ML libraries like `torch`, `tensorflow`, `sklearn`, etc.
- **Model File Detection**: Flags model files (e.g., `.h5`, `.pt`) to monitor asset usage.
- **Weight Operation Detection**: Detects code loading model weights to ensure model integrity.
- **Pre-trained Model Usage Detection**: Highlights pre-trained models (e.g., `ResNet`, `GPT`) in the code.
- **External Download Detection**: Flags external download commands to prevent unauthorized file imports.

## Prerequisites
- **Python 3.6+**
- **Git**: Make sure Git is installed and initialized in the project directory.

## Setup Instructions
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/your-repo-name.git
   cd your-repo-name