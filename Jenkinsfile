pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                git url: 'https://github.com/Devendra6666/NESTLE-POC.git', branch: 'main'
            }
        }

        stage('Run Validation') {
            steps {
                // If your Jenkins agent is Linux/macOS:
                sh '''
                    python validate.py \
                      --test-execution-key ITNPP-33 \
                      --test-case-3-key ITNPP-51 \
                      --test-case-4-key ITNPP-70 \
                      --test-case-5-key ITNPP-130 \
                '''
                // If using Windows agent, use the following instead:
                // bat "python validate.py --test-execution-key ITNPP-33 --test-case-key ITNPP-32 --test-case-2-key ITNPP-40 --test-case-4-key ITNPP-70 --test-case-3-key ITNPP-51"
            }
        }
    }

    post {
        always {
            echo 'Build complete.'
        }
        success {
            echo 'Validation ran successfully!'
        }
        failure {
            echo 'Something went wrong during validation.'
        }
    }
}

