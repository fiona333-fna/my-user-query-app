# AWS Provider
terraform {
  required_providers {
    aws = {
        source  = "hashicorp/aws"
        version = "~> 6.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
    region = "ap-northeast-1"
}

# Create a VPC
resource "aws_vpc" "main" {
    cidr_block = "10.0.0.0/16"
    enable_dns_hostnames = true
    enable_dns_support   = true
    tags = {
        Name = "my-project-vpc"
    }
}

resource "aws_internet_gateway" "gw" {
    vpc_id = aws_vpc.main.id

    tags = {
        Name = "my-project-igw"
    }
}

# Create three subnets

resource "aws_subnet" "public_subnet" {

    vpc_id                  = aws_vpc.main.id
    cidr_block              = "10.0.1.0/24"
    availability_zone       = "ap-northeast-1a" 
    map_public_ip_on_launch = true               

    tags = {
        Name = "public-subnet-1"
    }
}

resource "aws_subnet" "private_subnet" {
    vpc_id                  = aws_vpc.main.id
    cidr_block              = "10.0.2.0/24"
    availability_zone       = "ap-northeast-1c" 

    tags = {
        Name = "private-subnet-1"
    }
}

resource "aws_subnet" "private_subnet_2" {
    vpc_id                  = aws_vpc.main.id
    cidr_block              = "10.0.3.0/24"      
    availability_zone       = "ap-northeast-1d"  
    tags = { Name = "private-subnet-2" }
}

# Create Route table
resource "aws_route_table" "public_rt" {
    vpc_id = aws_vpc.main.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.gw.id
    }

    tags = {
        Name = "public-route-table"
    }
}

# Associate route table with public subnet
resource "aws_route_table_association" "public_rt_assoc" {
    subnet_id      = aws_subnet.public_subnet.id
    route_table_id = aws_route_table.public_rt.id
}

# Create　EIP for NAT Gateway
resource "aws_eip" "nat" {
    depends_on = [aws_internet_gateway.gw] 
    tags = { Name = "Project-NAT-EIP" }
}

# NAT gateway in public subnet
resource "aws_nat_gateway" "nat_gw" {
    allocation_id = aws_eip.nat.id
    subnet_id     = aws_subnet.public_subnet.id  

    tags = {
        Name = "Project-NAT-Gateway"
    }
}

# Create private route table
resource "aws_route_table" "private_rt" {
    vpc_id = aws_vpc.main.id
    tags = {
        Name = "private-route-table"
    }
}

# NAT Gateway -> Private Route Table
resource "aws_route" "private_nat_route" {
    route_table_id         = aws_route_table.private_rt.id
    destination_cidr_block = "0.0.0.0/0"
    nat_gateway_id         = aws_nat_gateway.nat_gw.id
}

# Associate private route table with private subnet
resource "aws_route_table_association" "private_rt_assoc" {
    subnet_id      = aws_subnet.private_subnet.id
    route_table_id = aws_route_table.private_rt.id
}

# Associate private route table with private subnet2
resource "aws_route_table_association" "private_rt_assoc_2" {
    subnet_id      = aws_subnet.private_subnet_2.id
    route_table_id = aws_route_table.private_rt.id
}


# Create Security Group for EC2 （防火墙）

resource "aws_security_group" "web_sg" {
    name        = "web-security-group"
    description = "Allow internal traffic from API Gateway on port 80"
    vpc_id      = aws_vpc.main.id

    # Ingress rule for EC2 (Python login in 8080)   
    ingress {
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"        
        cidr_blocks = [
        aws_subnet.private_subnet.cidr_block,
        aws_subnet.private_subnet_2.cidr_block
        ]  
    }

    # Egress rule
    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "web-sg"
    }
}

# Create Security Group for RDS （防火墙）
resource "aws_security_group" "db_sg" {
    name        = "db-security-group"
    description = "Allow MySQL traffic only from EC2"
    vpc_id      = aws_vpc.main.id

    ingress {
        from_port   = 3306
        to_port     = 3306
        protocol    = "tcp"
        security_groups = [aws_security_group.web_sg.id]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "db-sg"
    }
}

# Create IAM
resource "aws_iam_role" "ec2_ssm_role" {
    name = "ec2-ssm-role"


    assume_role_policy = jsonencode({
        Version = "2012-10-17",
        Statement = [
        {
            Action = "sts:AssumeRole",
            Effect = "Allow",
            Principal = {
            Service = "ec2.amazonaws.com"
            }
        }
        ]
    })

    tags = {
        Name = "ec2-ssm-role"
    }
}

resource "aws_iam_role_policy_attachment" "ssm_policy_attach" {
    role       = aws_iam_role.ec2_ssm_role.name
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_profile" {
    name = "ec2-ssm-instance-profile"
    role = aws_iam_role.ec2_ssm_role.name
}

# Amazon Linux 2 AMI
data "aws_ami" "amazon_linux_2" {
    most_recent = true
    owners      = ["amazon"]
    filter {
        name   = "name"
        values = ["amzn2-ami-hvm-*-x86_64-gp2"]
    }
}

# Create EC2 Instance (user_data)
resource "aws_instance" "web_server" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private_subnet.id
  vpc_security_group_ids      = [aws_security_group.web_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = false

  user_data = <<-EOF
    #!/bin/bash
    set -e 

    # 1. Install Nginx
    sudo amazon-linux-extras install nginx1 -y
    
    # 2. Install Python 3, pip, git, python
    sudo yum install python3-pip git mysql -y
    
    # 3. Install flask
    sudo pip3 install flask pymysql dbutils
    
    # 4. Create Nignx configure
    sudo tee /etc/nginx/conf.d/flask_proxy.conf > /dev/null <<'EOT'
server {
    listen 80;
    server_name _;

    # A. NLB check
    location = / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # B. API Gateway "prod" 
    location /prod/ {
        # --- CORS Preflight (OPTIONS) Handling ---
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS, HEAD';
            add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization, X-Amz-Date, X-Api-Key, X-Amz-Security-Token';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset-utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
        # --- Actual Request Handling ---
        add_header 'Access-Control-Allow-Origin' '*' always;
        
        # /prod/getinfo -> /getinfo
        proxy_pass http://127.0.0.1:8080/; 
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOT

    # 5. create path
    sudo mkdir -p /opt/app
    
    # 6. DB Environment
    sudo tee /etc/myapp.conf > /dev/null <<EOT
DB_HOST=${aws_db_instance.default.address}
DB_USER=${aws_db_instance.default.username}
DB_PASS=${var.db_password}
DB_NAME=${aws_db_instance.default.db_name}
EOT
    
    # 7. Create systemd Logfile
    sudo tee /etc/systemd/system/myapp.service > /dev/null <<'EOT'
[Unit]
Description=My Python Flask App
After=network.target

[Service]
User=ec2-user
Group=ec2-user
WorkingDirectory=/opt/app
EnvironmentFile=/etc/myapp.conf
ExecStart=/usr/bin/python3 app.py
Restart=always 
RestartSec=10

[Install]
WantedBy=multi-user.target
EOT

    # 8. Clone
    sudo git clone https://github.com/fiona333-fna/my-user-query-app.git /opt/app

    # 9. User Chown
    sudo chown -R ec2-user:ec2-user /opt/app

    # 10. Start services
    sudo systemctl daemon-reload
    sudo systemctl start nginx
    sudo systemctl enable nginx
    sudo systemctl enable myapp.service 
    sudo systemctl start myapp.service 
  EOF

  tags = { Name = "Python-API-Server" }

  depends_on = [aws_db_instance.default]
}

# Create VPC Link
resource "aws_apigatewayv2_vpc_link" "api_vpc_link" {
  name        = "project-api-vpc-link"
  subnet_ids  = [aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id] 
  security_group_ids = [aws_security_group.web_sg.id]
  tags = { Name = "project-api-vpc-link" }
}

resource "aws_lb" "api_nlb" {
    name               = "api-backend-nlb"
    internal           = true 
    load_balancer_type = "network" 
    subnets            = [aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id] 
    
    tags = {
        Name = "API-Backend-NLB"
    }
}

resource "aws_lb_target_group" "api_tg" {
    name     = "api-nlb-tg"
    port     = 80 
    protocol = "TCP" 
    vpc_id   = aws_vpc.main.id
    health_check {
        path = "/" 
        protocol = "HTTP"
        matcher = "200"
        interval = 30
        timeout = 5
    }
}

resource "aws_lb_listener" "api_listener" {
    load_balancer_arn = aws_lb.api_nlb.arn
    port              = 80
    protocol          = "TCP"

    default_action {
        type             = "forward"
        target_group_arn = aws_lb_target_group.api_tg.arn
    }
}

resource "aws_lb_target_group_attachment" "api_tg_attach" {
    target_group_arn = aws_lb_target_group.api_tg.arn
    target_id        = aws_instance.web_server.id
    port             = 80
}

# Create API Gateway REST API
resource "aws_apigatewayv2_api" "api" {
    name          = "Project-User-Service-API"
    protocol_type = "HTTP"    
}

resource "aws_apigatewayv2_integration" "api_integration" {
    api_id             = aws_apigatewayv2_api.api.id
    integration_type   = "HTTP_PROXY"
    integration_method = "ANY"
    integration_uri    = aws_lb_listener.api_listener.arn
    connection_type    = "VPC_LINK"
    connection_id      = aws_apigatewayv2_vpc_link.api_vpc_link.id
    payload_format_version = "1.0"
}

resource "aws_apigatewayv2_route" "default_route" {
    api_id    = aws_apigatewayv2_api.api.id
    route_key = "$default" 
    target    = "integrations/${aws_apigatewayv2_integration.api_integration.id}"
}

resource "aws_apigatewayv2_stage" "api_stage" {
    api_id      = aws_apigatewayv2_api.api.id
    name        = "prod"
    auto_deploy = true
    tags = {
    LastBackendInstanceID = aws_instance.web_server.id
    }
    depends_on = [ aws_apigatewayv2_route.default_route ]
}

# RDS subnet
resource "aws_db_subnet_group" "db_subnet_group" {
    name       = "my-db-subnet-group"
    subnet_ids = [aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id]

    tags = {
        Name = "My DB Subnet Group"
    }
}

# DB variable
variable "db_password" {
    description = "The password for the RDS database"
    type        = string
    sensitive   = true 
}

# Create RDS Instance
resource "aws_db_instance" "default" {
    identifier             = "my-project-db"
    allocated_storage      = 20 
    db_name                = "user_service_db"  
    engine                 = "mysql"
    engine_version         = "8.0"
    instance_class         = "db.t3.micro"    
    username               = "admin"   
    password               = var.db_password      
    db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name  
    vpc_security_group_ids = [aws_security_group.db_sg.id] 
    publicly_accessible  = false
    skip_final_snapshot    = true
}


# S3 static html （React）
resource "aws_s3_bucket" "frontend_bucket" {
  
    bucket = "my-unique-user-query-app-fiona" 

    tags = {
        Name = "React Frontend Bucket"
    }
}

resource "aws_s3_bucket_public_access_block" "frontend_bucket_pac" {
    bucket = aws_s3_bucket.frontend_bucket.id

    block_public_acls       = false
    block_public_policy     = false
    ignore_public_acls      = false
    restrict_public_buckets = false
}

# Load index.html to S3
resource "aws_s3_object" "frontend_index" {
  bucket = aws_s3_bucket.frontend_bucket.id
  key    = "index.html"
  content = templatefile("${path.module}/index.html", {
    api_url = aws_apigatewayv2_stage.api_stage.invoke_url
  })
  
  content_type = "text/html"
  depends_on = [aws_apigatewayv2_stage.api_stage]
}

resource "aws_s3_object" "js_files" {
  for_each = fileset("${path.module}/js", "*.js")
  
  bucket = aws_s3_bucket.frontend_bucket.id
  key    = "js/${each.value}"
  source = "${path.module}/js/${each.value}"
  content_type = "application/javascript"
  acl    = "public-read"
}

resource "aws_s3_bucket_website_configuration" "frontend_website" {
  bucket = aws_s3_bucket.frontend_bucket.id

  index_document {
    suffix = "index.html"
  }
}

# S3 Policy
resource "aws_s3_bucket_policy" "allow_public_read" {
    bucket = aws_s3_bucket.frontend_bucket.id
    policy = jsonencode({
        Version = "2012-10-17",
        Statement = [
        {
            Sid    = "PublicReadGetObject",
            Effect = "Allow",
            Principal = "*",  
            Action = "s3:GetObject", 
            Resource = "${aws_s3_bucket.frontend_bucket.arn}/*" 
        }
        ]
    })

    depends_on = [
        aws_s3_bucket_public_access_block.frontend_bucket_pac
    ]
}


# Output
output "frontend_url" {
    description = "The URL for the React (S3) frontend"
    value       = aws_s3_bucket_website_configuration.frontend_website.website_endpoint
}

output "backend_api_url" {
    description = "The FINAL HTTPS endpoint URL of the API Gateway"
    value       = aws_apigatewayv2_stage.api_stage.invoke_url
}

output "database_address" {
    description = "The hostname of the RDS (MySQL) database. Use this in Python."
    value       = aws_db_instance.default.address
}