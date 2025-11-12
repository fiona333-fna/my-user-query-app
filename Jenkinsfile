pipeline {
    agent any 
    tools {
        terraform 'default-terraform' // 假设您在 Jenkins 中配置了名为 'default-terraform' 的工具
    }
    environment {
        AWS_REGION = 'ap-northeast-1'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Provision Infrastructure (IaC)') {
            steps {
                // 【已添加】同时注入 AWS 凭证和数据库密码
                withCredentials([
                    aws(credentialsId: 'AWS_CREDS'), 
                    string(credentialsId: 'DB_PASSWORD', variable: 'TF_VAR_db_password')
                ]) {
                    sh 'terraform init'
                    sh 'terraform apply -auto-approve'
                }

                // 【已添加】aws 命令也需要凭证 (虽然 terraform output 不直接调用 aws，但保持一致性是好的)
                withCredentials([aws(credentialsId: 'AWS_CREDS')]) {
                    sh 'terraform output -json > tf_outputs.json'
                }
                
                script {
                    def outputs = readJSON file: 'tf_outputs.json'
                    env.DB_HOST_ADDRESS = outputs.database_address.value
                    env.EC2_INSTANCE_ID = readJSON(text: outputs.backend_api_url.value).LastBackendInstanceID 
                    env.S3_BUCKET_NAME = outputs.frontend_url.value.split('/')[2].split('.')[0]
                }
            }
        }

        stage('DB Migration') {
            steps {
                script {
                    // 【已添加】aws ec2 命令需要 AWS 凭证
                    withCredentials([
                        aws(credentialsId: 'AWS_CREDS'),
                        string(credentialsId: 'DB_PASSWORD', variable: 'DB_PASS'),
                        sshUserPrivateKey(credentialsId: 'EC2_SSH_KEY', keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER')
                    ]) {
                        
                        def instanceIp = sh(script: "aws ec2 describe-instances --instance-ids ${env.EC2_INSTANCE_ID} --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text", returnStdout: true).trim()
                        sh "scp -i ${SSH_KEY_FILE} -o StrictHostKeyChecking=no schema.sql ${SSH_USER}@${instanceIp}:/tmp/schema.sql"
                        sh """
                        ssh -i ${SSH_KEY_FILE} -o StrictHostKeyChecking=no ${SSH_USER}@${instanceIp} \
                        "mysql -h ${env.DB_HOST_ADDRESS} -u admin -p'${DB_PASS}' ${DB_NAME} < /tmp/schema.sql"
                        """
                    }
                }
            }
        }
        
        stage('Deploy Application (Backend)') {
            steps {
                script {
                    // 【已添加】aws ec2 命令需要 AWS 凭证
                    withCredentials([
                        aws(credentialsId: 'AWS_CREDS'),
                        sshUserPrivateKey(credentialsId: 'EC2_SSH_KEY', keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER')
                    ]) {
                        
                        def instanceIp = sh(script: "aws ec2 describe-instances --instance-ids ${env.EC2_INSTANCE_ID} --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text", returnStdout: true).trim()

                        sh "scp -i ${SSH_KEY_FILE} -o StrictHostKeyChecking=no app.py ${SSH_USER}@${instanceIp}:/opt/app/app.py"
                        sh "ssh -i ${SSH_KEY_FILE} -o StrictHostKeyChecking=no ${SSH_USER}@${instanceIp} 'sudo systemctl restart myapp.service'"
                    }
                }
            }
        }

        stage('Deploy Application (Frontend)') {
            steps {
                // 【已添加】aws s3 命令需要 AWS 凭证
                withCredentials([aws(credentialsId: 'AWS_CREDS')]) {
                    sh "aws s3 sync . s3://${env.S3_BUCKET_NAME} --exclude '*' --include 'index.html' --include 'js/*'"
                }
            }
        }
    }
}