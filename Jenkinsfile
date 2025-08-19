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
                sh '''
                    # Run Python script unbuffered so all prints appear in console
                    python3 -u $WORKSPACE/validate.py \
                      --test-execution-key ITNPP-33 \
                      --test-case-3-key ITNPP-51 \
                      --test-case-4-key ITNPP-70 \
                      --test-case-5-key ITNPP-130
                '''
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
