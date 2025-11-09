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

# Create two subnets
# EC2(Public subnet) + RDS(Private Subnet)

resource "aws_subnet" "public_subnet" {

    vpc_id                  = aws_vpc.main.id
    cidr_block              = "10.0.1.0/24"
    availability_zone       = "ap-northeast-1a" 
    map_public_ip_on_launch = true              # EC2启动的时候自动获得IP，与外部进行网络通信

    tags = {
        Name = "public-subnet-1"
    }
}

resource "aws_subnet" "private_subnet" {
    vpc_id                  = aws_vpc.main.id
    cidr_block              = "10.0.2.0/24"
    availability_zone       = "ap-northeast-1a" 

    tags = {
        Name = "private-subnet-1"
    }
}

resource "aws_subnet" "private_subnet_2" {
    vpc_id                  = aws_vpc.main.id
    cidr_block              = "10.0.3.0/24"      
    availability_zone       = "ap-northeast-1c"  
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

# Create Security Group for EC2 （防火墙）

resource "aws_security_group" "web_sg" {
    name        = "web-security-group"
    description = "Allow API (8080) traffic"
    vpc_id      = aws_vpc.main.id

    # Ingress rule for EC2 (Python login in 8080)
    ingress {
        from_port   = 8080
        to_port     = 8080
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"] 
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

# Create EC2 Instance

resource "aws_instance" "web_server" {
    ami           = data.aws_ami.amazon_linux_2.id
    instance_type = "t3.micro" 
    subnet_id = aws_subnet.public_subnet.id        
    vpc_security_group_ids = [aws_security_group.web_sg.id] 
    iam_instance_profile = aws_iam_instance_profile.ec2_profile.name 

    tags = {
        Name = "Python-API-Server"
    }
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
    description = "The Public DNS of the Python (EC2) server. Use this in React's fetch()."
    value       = "http://${aws_instance.web_server.public_ip}:8080"
}

output "database_address" {
    description = "The hostname of the RDS (MySQL) database. Use this in Python."
    value       = aws_db_instance.default.address
}