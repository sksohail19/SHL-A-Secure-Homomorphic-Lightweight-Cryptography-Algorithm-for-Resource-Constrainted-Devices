# SHL DevOps Project

This repository contains the implementation of a custom encryption and decryption process written in Python, along with a complete DevOps pipeline setup. The project demonstrates secure data handling while leveraging modern DevOps tools for deployment and scalability.

---

## Directory Structure

```
SHL-DevOps/
├── ansible/
│   ├── playbook.yml       # Ansible playbook for automated deployment
│   ├── hosts              # Ansible inventory file
├── terraform/
│   ├── main.tf            # Terraform configuration file for provisioning resources
│   ├── variables.tf       # Terraform variables file
│   ├── outputs.tf         # Terraform outputs file
├── k8s/
│   ├── deployment.yml     # Kubernetes Deployment manifest
│   ├── service.yml        # Kubernetes Service manifest
├── src/
│   ├── EncryptionProcess.py  # Python script for encryption process
│   ├── DecryptionProcess.py  # Python script for decryption process
│   ├── main.py               # Entry point script for user interaction
│   ├── Dockerfile            # Dockerfile for containerizing the application
│   ├── requirements.txt      # Python dependencies
├── Jenkinsfile             # Jenkins pipeline definition
└── ReadMe.md               # Project documentation
```

---

## Features

1. **Custom Encryption and Decryption**:
   - Implements a secure encryption and decryption mechanism using Python.
   - Utilizes HKDF for key derivation and cryptographic operations.

2. **DevOps Pipeline**:
   - **Ansible**: Automates deployment on servers.
   - **Terraform**: Manages cloud infrastructure.
   - **Docker**: Containerizes the application for consistency and portability.
   - **Kubernetes**: Orchestrates the deployment and scaling of the application.
   - **Jenkins**: Automates CI/CD pipeline for building, testing, and deploying the application.

---

## Prerequisites

- **Python**: `>=3.8`
- **Docker**: `>=20.10`
- **Kubernetes**: `>=1.20`
- **Terraform**: `>=1.0`
- **Ansible**: `>=2.9`
- **Jenkins**: Installed and configured for CI/CD

---

## Setup and Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-repo/SHL-DevOps.git
cd SHL-DevOps
```

### Step 2: Install Python Dependencies
```bash
pip install -r src/requirements.txt
```

### Step 3: Build Docker Image
```bash
cd src
docker build -t shl-devops-app .
```

### Step 4: Deploy Using Kubernetes
```bash
kubectl apply -f k8s/deployment.yml
kubectl apply -f k8s/service.yml
```

---

## Usage

1. **Run the Application Locally**:
   ```bash
   python3 src/main.py
   ```
   Follow the prompts to encrypt or decrypt messages.

2. **Run the Application in a Container**:
   ```bash
   docker run -it shl-devops-app
   ```

3. **Access the Application on Kubernetes**:
   - Find the service's external IP:
     ```bash
     kubectl get svc
     ```
   - Access the service using the displayed IP and port.

---

## CI/CD Pipeline

- **Jenkinsfile**: Defines the pipeline steps for:
  - Pulling the latest code from the repository
  - Building and testing the Docker image
  - Pushing the Docker image to a container registry
  - Deploying to a Kubernetes cluster

---

## Infrastructure Management

- **Terraform**:
  - Provisions cloud infrastructure such as servers, networks, and storage.

- **Ansible**:
  - Installs dependencies and configures the environment for the application.

---

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Author

**Sohail Shaik**

Feel free to reach out for any questions or collaboration opportunities.

