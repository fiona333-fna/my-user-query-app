terraform {
  required_providers {
    aws = {
        source  = "hashicorp/aws"
        version = "~> 6.0"
    }
  }
}

provider "aws" {
    region = "ap-northeast-1"
}

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

resource "aws_route_table_association" "public_rt_assoc" {
    subnet_id      = aws_subnet.public_subnet.id
    route_table_id = aws_route_table.public_rt.id
}

resource "aws_eip" "nat" {
    depends_on = [aws_internet_gateway.gw] 
    tags = { Name = "Project-NAT-EIP" }
}

resource "aws_nat_gateway" "nat_gw" {
    allocation_id = aws_eip.nat.id
    subnet_id     = aws_subnet.public_subnet.id  
    tags = {
        Name = "Project-NAT-Gateway"
    }
}

resource "aws_route_table" "private_rt" {
    vpc_id = aws_vpc.main.id
    tags = {
        Name = "private-route-table"
    }
}

resource "aws_route" "private_nat_route" {
    route_table_id         = aws_route_table.private_rt.id
    destination_cidr_block = "0.0.0.0/0"
    nat_gateway_id         = aws_nat_gateway.nat_gw.id
}

resource "aws_route_table_association" "private_rt_assoc" {
    subnet_id      = aws_subnet.private_subnet.id
    route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_rt_assoc_2" {
    subnet_id      = aws_subnet.private_subnet_2.id
    route_table_id = aws_route_table.private_rt.id
}

resource "aws_security_group" "web_sg" {
    name        = "web-security-group"
    description = "Allow internal traffic from API Gateway on port 80"
    vpc_id      = aws_vpc.main.id
    ingress {
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"        
        cidr_blocks = [
        aws_subnet.private_subnet.cidr_block,
        aws_subnet.private_subnet_2.cidr_block
        ]  
    }
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

data "aws_ami" "amazon_linux_2" {
    most_recent = true
    owners      = ["amazon"]
    filter {
        name   = "name"
        values = ["amzn2-ami-hvm-*-x86_64-gp2"]
    }
}

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

    sudo amazon-linux-extras install nginx1 -y
    
    sudo yum install python3-pip git mysql java-17-amazon-corretto -y 
    
    sudo pip3 install flask pymysql dbutils
    
    FLYWEY_VERSION="9.22.3"
    FLYWEY_HOME="/opt/flyway"
    
    echo "Creating Flyway directories: $${FLYWEY_HOME}/sql/db/migration"
    sudo mkdir -p $${FLYWEY_HOME}/sql/db/migration
    
    echo "Downloading and installing Flyway..."
    wget -q https://repo1.maven.org/maven2/org/flywaydb/flyway-commandline/$${FLYWEY_VERSION}/flyway-commandline-$${FLYWEY_VERSION}.tar.gz
    
    tar -xzf flyway-commandline-$${FLYWEY_VERSION}.tar.gz -C /tmp/
    sudo mv /tmp/flyway-$${FLYWEY_VERSION} $${FLYWEY_HOME}
    
    sudo ln -s $${FLYWEY_HOME}/flyway /usr/local/bin/flyway
    sudo chown -R ec2-user:ec2-user $${FLYWEY_HOME}
    
    sudo mkdir -p /opt/app
    
    sudo tee /etc/myapp.conf > /dev/null <<EOT
DB_HOST=${aws_db_instance.default.address}
DB_USER=${aws_db_instance.default.username}
DB_PASS=${var.db_password}
DB_NAME=${aws_db_instance.default.db_name}
EOT
    
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

    sudo git clone https://github.com/fiona333-fna/my-user-query-app.git /opt/app

    sudo chown -R ec2-user:ec2-user /opt/app

    sudo systemctl daemon-reload
    sudo systemctl start nginx
    sudo systemctl enable nginx
    sudo systemctl enable myapp.service 
    sudo systemctl start myapp.service 
  EOF

  tags = { Name = "Python-API-Server" }
  depends_on = [aws_db_instance.default]
}

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

resource "aws_db_subnet_group" "db_subnet_group" {
    name       = "my-db-subnet-group"
    subnet_ids = [aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id]
    tags = {
        Name = "My DB Subnet Group"
    }
}

variable "db_password" {
    description = "The password for the RDS database"
    type        = string
    sensitive   = true 
}

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

resource "aws_s3_object" "frontend_index" {
  bucket = aws_s3_bucket.frontend_bucket.id
  key    = "index.html"
  
  content = replace(
    file("${path.module}/index.html"),
    "$${api_url}",
    aws_apigatewayv2_stage.api_stage.invoke_url
  )
  
  content_type = "text/html"
  depends_on = [aws_apigatewayv2_stage.api_stage]
}

resource "aws_s3_object" "js_files" {
  for_each = fileset("${path.module}/js", "*.js")
  
  bucket = aws_s3_bucket.frontend_bucket.id
  key    = "js/${each.value}"
  source = "${path.module}/js/${each.value}"
  content_type = "application/javascript"
}

resource "aws_s3_bucket_website_configuration" "frontend_website" {
  bucket = aws_s3_bucket.frontend_bucket.id
  index_document {
    suffix = "index.html"
  }
}

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