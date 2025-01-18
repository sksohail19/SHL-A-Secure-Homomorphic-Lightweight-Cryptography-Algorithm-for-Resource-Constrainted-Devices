pipeline {
    agent any
    stages {
        stage('Clone Repository') {
            steps {
                git "https://github.com/sksohail19/SHL-A-Secure-Homomorphic-Lightweight-Cryptography-Algorithm-for-Resource-Constrainted-Devices.git"
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t shl-app src/'
            }
        }

        stage('Run Docker Container') {
            steps {
                sh 'docker run -d -p 8080:8080 shl-app'
            }
        }

        stage('Run Tests') {
            steps{
                sh 'docker run shl-app pytest'
            }
        }

        stage('Deploy to kubernetes') {
            steps {
                sh 'kubectl apply -f k8s/deployment.yaml'
                sh 'kubectl apply -f k8s/service.yaml'
            }
        }
    }
}