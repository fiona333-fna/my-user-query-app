// Jenkinsfile (已修复 'Provision' 阶段)

pipeline {
    agent any 
    tools {
        terraform 'default-terraform'
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

        stage('Check Tools') {
            steps {
                sh 'terraform version'
                sh 'aws --version'
                sh 'jq --version'
                sh 'mysql --version'
                sh 'ssh -V'
            }
        }

        // V V V V V V 【修改此阶段】 V V V V V V
        stage('Provision Infrastructure (IaC)') {
            steps {
                // 【新增】强制清理旧的缓存和锁定文件
                // 这可以解决插件损坏或状态锁定的问题
                sh 'echo "Cleaning up previous Terraform state..."'
                sh 'rm -rf .terraform .terraform.lock.hcl'

                // 注入凭证以运行 'init'
                withCredentials([
                    aws(credentialsId: 'AWS_CREDS'), 
                    string(credentialsId: 'DB_PASSWORD', variable: 'TF_VAR_db_password')
                ]) {
                    // -reconfigure 确保它重新检查后端配置
                    sh 'terraform init -reconfigure'
                }

                // 【新增】单独运行 'plan'
                // 'plan' 也会加载插件。如果这里失败，说明问题就在于加载插件
                // 这一步是关键的调试步骤
                sh 'echo "Running Terraform Plan..."'
                withCredentials([
                    aws(credentialsId: 'AWS_CREDS'), 
                    string(credentialsId: 'DB_PASSWORD', variable: 'TF_VAR_db_password')
                ]) {
                    sh 'terraform plan'
                }

                // 只有 'plan' 成功后，才运行 'apply'
                sh 'echo "Running Terraform Apply..."'
                withCredentials([
                    aws(credentialsId: 'AWS_CREDS'), 
                    string(credentialsId: 'DB_PASSWORD', variable: 'TF_VAR_db_password')
                ]) {
                    sh 'terraform apply -auto-approve'
                }
                
                // 【保持不变】获取输出
                withCredentials([aws(credentialsId: 'AWS_CREDS')]) {
                    sh 'terraform output -json > tf_outputs.json'
                }
                
                script {
                    def outputs = readJSON file: 'tf_outputs.json'
                    env.DB_HOST_ADDRESS = outputs.database_address.value
                    sh 'terraform state show -json aws_s3_bucket.frontend_bucket > s3.json'
                    def s3 = readJSON file: 's3.json'
                    env.S3_BUCKET_NAME = s3.values.bucket
                    sh 'terraform state show -json aws_instance.web_server > ec2.json'
                    def ec2 = readJSON file: 'ec2.json'
                    env.EC2_INSTANCE_ID = ec2.values.id
                }
            }
        }
        // A A A A A A 【修改结束】 A A A A A A

        stage('DB Migration') {
            // ... (此阶段及后续阶段保持不变) ...
            steps {
                script {
                    withCredentials([
                        aws(credentialsId: 'AWS_CREDS'),
                        string(credentialsId: 'DB_PASSWORD', variable: 'DB_PASS'),
                        sshUserPrivateKey(credentialsId: 'EC2_SSH_KEY', keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER')
                    ]) {
                        
                        def instanceIp = sh(script: "aws ec2 describe-instances --instance-ids ${env.EC2_INSTANCE_ID} --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text", returnStdout: true).trim()
                        
                        sh "scp -i ${SSH_KEY_FILE} -o StrictHostKeyChecking=no schema.sql ${SSH_USER}@${instanceIp}:/tmp/schema.sql"
                        sh """
                        ssh -i ${SSH_KEY_FILE} -o StrictHostKeyChecking=no ${SSH_USER}@${instanceIp} \
                        "mysql -h ${env.DB_HOST_ADDRESS} -u admin -p'${DB_PASS}' user_service_db < /tmp/schema.sql"
                        """
                    }
                }
            }
        }
        
        stage('Deploy Application (Backend)') {
            // ... (不变) ...
        }

        stage('Deploy Application (Frontend)') {
            // ... (不变) ...
        }
    }
}