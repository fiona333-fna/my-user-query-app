pipeline {
    // 1. 【修改】指定一个 Docker Agent
    // 我们将使用官方的 Terraform 镜像，并以 root 身份运行以便安装工具
    agent {
        docker {
            image 'hashicorp/terraform:latest'
            args '-u root' 
        }
    }

    // 【已删除】不再需要 tools 块，Docker 镜像自带 Terraform
    
    environment {
        AWS_REGION = 'ap-northeast-1'
        // 【已删除】不再需要 TF_PLUGIN_TIMEOUT，Docker 环境通常资源更足
    }

    stages {
        
        // 2. 【新增】在所有工作开始前，准备好所有工具
        stage('Prepare Environment') {
            steps {
                sh 'apk update' // 这是 Terraform 镜像(Alpine Linux)的包管理器
                
                // 安装所有缺失的工具：
                // 1. aws-cli (用于 aws 命令)
                // 2. jq (用于解析 JSON)
                // 3. openssh-client (用于 ssh 和 scp)
                // 4. mysql-client (用于 DB Migration)
                sh 'apk add aws-cli jq openssh-client mysql-client'
                
                // 验证一下
                sh 'terraform version'
                sh 'aws --version'
                sh 'jq --version'
                sh 'mysql --version'
            }
        }

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Provision Infrastructure (IaC)') {
            steps {
                withCredentials([
                    aws(credentialsId: 'AWS_CREDS'), 
                    string(credentialsId: 'DB_PASSWORD', variable: 'TF_VAR_db_password')
                ]) {
                    sh 'rm -rf .terraform .terraform.lock.hcl' // 清理缓存
                    sh 'terraform init'
                    sh 'terraform apply -auto-approve' // 在 Docker 容器中，资源通常更充足
                }

                // 3. 【修改】用更可靠的方式获取输出
                withCredentials([aws(credentialsId: 'AWS_CREDS')]) {
                    sh 'terraform output -json > tf_outputs.json'
                    sh 'terraform state show -json aws_s3_bucket.frontend_bucket > s3.json'
                    sh 'terraform state show -json aws_instance.web_server > ec2.json'
                }
                
                script {
                    def outputs = readJSON file: 'tf_outputs.json'
                    env.DB_HOST_ADDRESS = outputs.database_address.value
                    
                    def s3 = readJSON file: 's3.json'
                    env.S3_BUCKET_NAME = s3.values.bucket
                    
                    def ec2 = readJSON file: 'ec2.json'
                    env.EC2_INSTANCE_ID = ec2.values.id
                }
            }
        }

        stage('DB Migration') {
            steps {
                script {
                    withCredentials([
                        aws(credentialsId: 'AWS_CREDS'),
                        string(credentialsId: 'DB_PASSWORD', variable: 'DB_PASS'),
                        sshUserPrivateKey(credentialsId: 'EC2_SSH_KEY', keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER')
                    ]) {
                        def instanceIp = sh(script: "aws ec2 describe-instances --instance-ids ${env.EC2_INSTANCE_ID} --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text", returnStdout: true).trim()
                        
                        // 4. 【新增】在容器中正确设置 SSH 密钥
                        sh "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
                        sh "cp ${SSH_KEY_FILE} ~/.ssh/id_rsa && chmod 400 ~/.ssh/id_rsa"

                        // 使用相对路径 (更简单)
                        sh "scp -o StrictHostKeyChecking=no schema.sql ${SSH_USER}@${instanceIp}:/tmp/schema.sql"
                        sh """
                        ssh -o StrictHostKeyChecking=no ${SSH_USER}@${instanceIp} \
                        "mysql -h ${env.DB_HOST_ADDRESS} -u admin -p'${DB_PASS}' user_service_db < /tmp/schema.sql"
                        """
                    }
                }
            }
        }
        
        stage('Deploy Application (Backend)') {
            steps {
                script {
                    withCredentials([
                        aws(credentialsId: 'AWS_CREDS'),
                        sshUserPrivateKey(credentialsId: 'EC2_SSH_KEY', keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER')
                    ]) {
                        def instanceIp = sh(script: "aws ec2 describe-instances --instance-ids ${env.EC2_INSTANCE_ID} --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text", returnStdout: true).trim()
                        
                        // 5. 【新增】再次确保 SSH 密钥已设置
                        sh "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
                        sh "cp ${SSH_KEY_FILE} ~/.ssh/id_rsa && chmod 400 ~/.ssh/id_rsa"

                        // 使用相对路径
                        sh "scp -o StrictHostKeyChecking=no app.py ${SSH_USER}@${instanceIp}:/opt/app/app.py"
                        sh "ssh -o StrictHostKeyChecking=no ${SSH_USER}@${instanceIp} 'sudo systemctl restart myapp.service'"
                    }
                }
            }
        }

        stage('Deploy Application (Frontend)') {
            steps {
                withCredentials([aws(credentialsId: 'AWS_CREDS')]) {
                    // 6. 【修改】使用相对路径 "." (当前目录)
                    sh "aws s3 sync . s3://${env.S3_BUCKET_NAME} --exclude '*' --include 'index.html' --include 'js/*'"
                }
            }
        }
    }
}