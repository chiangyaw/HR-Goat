terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.0.0"
  
  backend "s3" {
    # These values will be set by GitHub Actions
    # Don't hardcode them here
  }
}

provider "aws" {
  region = var.aws_region
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}

# Get available availability zones in the current region
data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

# Get the most recent Amazon Linux 2 AMI
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Option 1: Amazon Linux 2023 (kernel 6.1+)
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Option 2: Ubuntu 22.04 LTS (kernel 5.15+)
data "aws_ami" "ubuntu_22_04" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Option 3: Ubuntu 20.04 LTS with HWE kernel (5.13+)
data "aws_ami" "ubuntu_20_04_hwe" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Option 4: Debian 11 (kernel 5.10, can be upgraded to 5.13+)
data "aws_ami" "debian_11" {
  most_recent = true
  owners      = ["136693071363"] # Debian

  filter {
    name   = "name"
    values = ["debian-11-amd64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Option 5: CentOS Stream 9 (Latest Stable)
# Using direct AMI lookup for CentOS Stream 9 in us-east-1
data "aws_ami" "centos_7" {  # Keeping variable name for compatibility
  most_recent = true
  owners      = ["125523088429"] # CentOS official account
  
  filter {
    name   = "name"
    values = ["CentOS Stream 9 x86_64*"]
  }
  
  filter {
    name   = "architecture" 
    values = ["x86_64"]
  }
  
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Local values for AMI selection based on kernel version
locals {
  ami_map = {
    "amazon-linux-2"     = data.aws_ami.amazon_linux_2.id
    "amazon-linux-2023"  = data.aws_ami.amazon_linux_2023.id
    "ubuntu-22-04"       = data.aws_ami.ubuntu_22_04.id
    "ubuntu-20-04-hwe"   = data.aws_ami.ubuntu_20_04_hwe.id
    "debian-11"          = data.aws_ami.debian_11.id
    "centos-7"           = data.aws_ami.centos_7.id
  }
  
  selected_ami = local.ami_map[var.ec2_kernel_version]
}

# Create a new VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-vpc"
  })
}

# Create public subnets
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-public-a"
  })
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-public-b"
  })
}

# Create Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-igw"
  })
}

# Create Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-public-rt"
  })
}

# Associate Route Table with Subnets
resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# Security Group for App EC2 instance
resource "aws_security_group" "app_sg" {
  name        = "${var.project_name}-app-sg"
  description = "Security group for App EC2 instance"
  vpc_id      = aws_vpc.main.id
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-app-sg"
  })

  ingress {
    description = "SSH from anywhere (for troubleshooting)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Node.js server port"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group for Jenkins EC2 instance
resource "aws_security_group" "jenkins_sg" {
  name        = "${var.project_name}-jenkins-sg"
  description = "Security group for Jenkins EC2 instance"
  vpc_id      = aws_vpc.main.id
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-jenkins-sg"
  })

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Jenkins web interface"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group for RDS
resource "aws_security_group" "rds_sg" {
  name        = "${var.project_name}-rds-sg"
  description = "Security group for RDS instance"
  vpc_id      = aws_vpc.main.id
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-rds-sg"
  })

  ingress {
    description     = "MySQL from App EC2"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  ingress {
    description     = "MySQL from Jenkins EC2"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.jenkins_sg.id]
  }

  ingress {
    description = "MySQL from anywhere (public access)"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
# IAM Role for EC2 to use SSM
resource "aws_iam_role" "ssm_role" {
  name = "${var.project_name}-ssm-role-${var.aws_region}"
  
  tags = var.common_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Create Jenkins IAM role for more permissions
resource "aws_iam_role" "jenkins_role" {
  name = "${var.project_name}-jenkins-role-${var.aws_region}"
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-jenkins-role-${var.aws_region}"
  })

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# 🔥 Inline Policy: Allow Jenkins to Attach AdministratorAccess to Itself
resource "aws_iam_role_policy" "jenkins_self_escalation" {
  name   = "jenkins-self-escalation"
  role   = aws_iam_role.jenkins_role.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "iam:AttachRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:GetRole",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-jenkins-role-${var.aws_region}"
      },
      {
        Effect   = "Allow"
        Action   = [
          "iam:ListPolicies",
          "iam:GetPolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

# Create instance profile for EC2
resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "${var.project_name}-ssm-instance-profile-${var.aws_region}"
  role = aws_iam_role.ssm_role.name
}

# Create instance profile for Jenkins
resource "aws_iam_instance_profile" "jenkins_instance_profile" {
  name = "${var.project_name}-jenkins-instance-profile-${var.aws_region}"
  role = aws_iam_role.jenkins_role.name
}

# Create Jenkins IAM policy
resource "aws_iam_policy" "jenkins_policy" {
  name        = "${var.project_name}-jenkins-policy-${var.aws_region}"
  description = "Policy for Jenkins instance with iam:PassRole and ec2:RunInstances permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "ec2:RunInstances"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "iam:CreateServiceLinkedRole"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "iam:AttachRolePolicy",
          "iam:CreatePolicy",
          "iam:CreatePolicyVersion"
        ]
        Resource = aws_iam_role.jenkins_role.arn
      }
    ]
  })
}

# Attach the Jenkins policy to the Jenkins role
resource "aws_iam_role_policy_attachment" "jenkins_policy_attachment" {
  role       = aws_iam_role.jenkins_role.name
  policy_arn = aws_iam_policy.jenkins_policy.arn
}

# Attach SSM policy to the Jenkins role
resource "aws_iam_role_policy_attachment" "jenkins_ssm_policy" {
  role       = aws_iam_role.jenkins_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}


# Attach S3 access for XDR installation to the Jenkins role
resource "aws_iam_role_policy_attachment" "jenkins_s3_policy" {
  role       = aws_iam_role.jenkins_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# Attach ECR policy to the Jenkins role
resource "aws_iam_role_policy_attachment" "jenkins_ecr_policy" {
  role       = aws_iam_role.jenkins_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess"
}

# Attach SSM policy to the ssm_role
resource "aws_iam_role_policy_attachment" "ssm_policy" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Attach ECR policy to the ssm_role
resource "aws_iam_role_policy_attachment" "ecr_policy" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess"
}

# Add S3 access for XDR installation to the ssm_role
resource "aws_iam_role_policy_attachment" "s3_policy" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# Add permissions for ssm_role to list instances, view its own roles/policies, and send SSM commands
resource "aws_iam_policy" "ssm_role_additional_permissions" {
  name        = "${var.project_name}-ssm-role-additional-permissions-${var.aws_region}"
  description = "Additional permissions for SSM role to list instances, view roles/policies, and send SSM commands"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:ListRoles",
          "iam:ListPolicies",
          "iam:GetPolicy",
          "iam:ListRolePolicies"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "ssm:SendCommand",
          "ssm:ListCommands",
          "ssm:ListCommandInvocations",
          "ssm:GetCommandInvocation"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach the additional permissions policy to the ssm_role
resource "aws_iam_role_policy_attachment" "ssm_role_additional_permissions_attachment" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = aws_iam_policy.ssm_role_additional_permissions.arn
}

# EC2 instance for the application
resource "aws_instance" "app_instance" {
  ami           = local.selected_ami  # AMI selected based on var.ec2_kernel_version
  instance_type = var.ec2_instance_type
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  subnet_id     = aws_subnet.public_a.id
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  key_name      = var.key_name != "" ? var.key_name : null

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Enforce IMDSv2
  }

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-app-instance"
  })

  user_data = <<-EOF
    #!/bin/bash
    # Update system
    set -ex

    # Log all commands for debugging
    exec > >(tee /var/log/user-data.log) 2>&1
    echo "Starting user data script execution at $(date)..."

    # Create a test file to verify script execution
    echo "Script executed at $(date)" > /tmp/script-executed.txt

    # Create application directory with explicit permissions
    mkdir -p /opt/hrApp
    chmod -R 777 /opt/hrApp
    echo "Created hrApp directory at $(date)" > /opt/hrApp/created.txt

    # Update system packages
    echo "Updating system packages..."
    export DEBIAN_FRONTEND=noninteractive
    
    # Retry apt-get update in case of lock issues
    for i in {1..5}; do
      if apt-get update -y; then
        break
      fi
      echo "apt-get update failed, waiting for lock release... attempt $i/5"
      sleep 10
    done
    
    apt-get install -y gnupg unzip curl

    # Install AWS CLI v2 system-wide
    echo "Installing AWS CLI v2..."
    cd /tmp
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    ./aws/install
    rm -rf awscliv2.zip aws/
    
    # Create symlink for AWS CLI
    ln -sf /usr/local/bin/aws /usr/bin/aws
    
    # Verify AWS CLI installation
    if ! aws --version; then
      echo "ERROR: AWS CLI installation failed!"
      exit 1
    fi
    echo "AWS CLI installed successfully: $(aws --version)"

    # Configure AWS CLI with the instance region
    echo "Configuring AWS CLI default region..."
    mkdir -p /root/.aws
    cat > /root/.aws/config <<EOL
    [default]
    region = ${var.aws_region}
    EOL
    
    # Also configure for ubuntu user
    mkdir -p /home/ubuntu/.aws
    cat > /home/ubuntu/.aws/config <<EOL
    [default]
    region = ${var.aws_region}
    EOL
    chown -R ubuntu:ubuntu /home/ubuntu/.aws

    # Configure global AWS region for all users
    echo "export AWS_DEFAULT_REGION=${var.aws_region}" >> /etc/profile.d/aws.sh
    chmod +x /etc/profile.d/aws.sh

    # Install and start SSM Agent
    echo "Installing and configuring SSM Agent..."
    # The snap might not be available immediately after boot. Retry a few times.
    for i in {1..5}; do
      if apt-get install -y snapd; then
        break
      fi
      echo "snapd installation failed, retrying... attempt $i/5"
      sleep 10
    done

    # Retry snap command
    for i in {1..5}; do
      if snap install amazon-ssm-agent --classic; then
        break
      fi
      echo "SSM agent snap installation failed, retrying... attempt $i/5"
      sleep 10
    done

    # Enable and start the agent
    systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
    systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service

    # Wait for agent to be active
    echo "Waiting for SSM Agent to become active..."
    for i in {1..10}; do
      if systemctl is-active --quiet snap.amazon-ssm-agent.amazon-ssm-agent.service; then
        echo "✓ SSM Agent is active."
        break
      fi
      echo "Waiting for SSM agent... attempt $i/10"
      sleep 10
    done

    # Install Docker
    echo "Installing Docker..."
    apt-get install -y apt-transport-https ca-certificates software-properties-common
    
    # Add Docker's official GPG key
    mkdir -p /etc/apt/keyrings
    for i in {1..3}; do
      if curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; then
        break
      fi
      echo "Failed to download Docker GPG key, retrying... attempt $i/3"
      sleep 5
    done
    
    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Update package index with Docker packages
    apt-get update -y
    
    # Install Docker
    for i in {1..3}; do
      if apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
        break
      fi
      echo "Docker installation failed, retrying... attempt $i/3"
      sleep 10
    done

    # Make sure Docker service is enabled and started
    echo "Enabling and starting Docker service..."
    systemctl enable docker
    systemctl start docker
    
    # Wait for Docker to be fully ready
    for i in {1..10}; do
      if docker version >/dev/null 2>&1; then
        echo "✓ Docker is ready."
        break
      fi
      echo "Waiting for Docker daemon... attempt $i/10"
      sleep 5
    done

    # Verify Docker is installed and running
    if ! docker --version; then
      echo "ERROR: Docker installation failed!"
      exit 1
    fi
    echo "Docker installed successfully: $(docker --version)"
    
    if ! systemctl is-active --quiet docker; then
      echo "ERROR: Docker service is not running!"
      exit 1
    fi

    # Add ubuntu user to docker group
    usermod -aG docker ubuntu
    
    # Also add ssm-user to docker group if it exists
    if id "ssm-user" &>/dev/null; then
        usermod -aG docker ssm-user
        echo "Added ssm-user to docker group"
    fi

    # Also ensure docker commands are in PATH
    echo 'export PATH="/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:$PATH"' >> /etc/profile.d/docker.sh
    chmod +x /etc/profile.d/docker.sh

    # Install additional development tools
    echo "Installing development tools..."
    apt-get install -y build-essential git wget

    # Final verification
    echo "=== Final System Status ===" | tee /tmp/user-data-complete.txt
    echo "Docker version: $(docker --version 2>&1)" | tee -a /tmp/user-data-complete.txt
    echo "AWS CLI version: $(aws --version 2>&1)" | tee -a /tmp/user-data-complete.txt
    echo "Docker service: $(systemctl is-active docker)" | tee -a /tmp/user-data-complete.txt
    echo "SSM Agent service: $(systemctl is-active snap.amazon-ssm-agent.amazon-ssm-agent.service)" | tee -a /tmp/user-data-complete.txt
    echo "Script completed at: $(date)" | tee -a /tmp/user-data-complete.txt
    
    # Only create deployment-ready marker if everything is successful
    if docker --version && aws --version && systemctl is-active --quiet docker; then
      touch /tmp/deployment-ready
      echo "✅ All tools installed successfully, instance is deployment-ready!" | tee -a /tmp/user-data-complete.txt
    else
      echo "❌ Some tools failed to install properly!" | tee -a /tmp/user-data-complete.txt
      exit 1
    fi
  EOF

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    tags = merge(var.common_tags, {
      Name = "${var.project_name}-app-volume"
    })
  }
}

# EC2 instance for Jenkins
resource "aws_instance" "jenkins_instance" {
  ami                    = local.selected_ami  # AMI selected based on var.ec2_kernel_version
  instance_type          = var.ec2_instance_type
  vpc_security_group_ids = [aws_security_group.jenkins_sg.id]
  subnet_id              = aws_subnet.public_a.id
  iam_instance_profile   = aws_iam_instance_profile.jenkins_instance_profile.name
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Enforce IMDSv2
  }
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-jenkins-instance"
  })

  user_data = <<-EOF
              #!/bin/bash
              # Set up logging
              exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
              echo "Starting Jenkins installation and configuration..."
              
              # CRITICAL: Install AWS CLI first using the exact commands provided
              echo "Installing AWS CLI v2 as first priority..."
              apt-get update -y
              apt-get install -y unzip
              
              curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
              unzip awscliv2.zip
              ./aws/install
              
              # Clean up installation files
              rm -rf awscliv2.zip aws/
              
              # Create symlinks for AWS CLI in all possible locations
              ln -sf /usr/local/bin/aws /usr/bin/aws
              ln -sf /usr/local/bin/aws /bin/aws
              
              # Ensure AWS CLI is in PATH for all users including SSM
              echo 'export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"' >> /etc/profile.d/aws-cli.sh
              chmod +x /etc/profile.d/aws-cli.sh
              
              # Also add to /etc/environment for non-login shells
              if ! grep -q "/usr/local/bin" /etc/environment; then
                sed -i 's|PATH="\(.*\)"|PATH="/usr/local/bin:\1"|' /etc/environment
              fi
              
              # Source the new PATH
              export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
              
              # Verify AWS CLI installation
              if ! /usr/local/bin/aws --version; then
                echo "ERROR: AWS CLI installation failed!"
                exit 1
              fi
              echo "AWS CLI installed successfully: $(/usr/local/bin/aws --version)"
              
              # Create AWS CLI ready marker
              touch /tmp/aws-cli-ready
              
              # Update system
              echo "Updating system packages..."
              apt-get update -y
              apt-get install -y gnupg
              
              # Install and start SSM Agent
              echo "Installing and configuring SSM Agent..."
              # Use DEBIAN_FRONTEND=noninteractive to avoid any prompts
              export DEBIAN_FRONTEND=noninteractive
              # The snap might not be available immediately after boot. Retry a few times.
              for i in {1..5}; do
                apt-get install -y snapd && break
                echo "snapd installation failed, retrying..."
                sleep 10
              done

              # Retry snap command
              for i in {1..5}; do
                snap install amazon-ssm-agent --classic && break
                echo "SSM agent snap installation failed, retrying..."
                sleep 10
              done

              # Enable and start the agent
              systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
              systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service

              # Wait for agent to be active
              echo "Waiting for SSM Agent to become active..."
              for i in {1..10}; do
                if systemctl is-active --quiet snap.amazon-ssm-agent.amazon-ssm-agent.service; then
                  echo "✓ SSM Agent is active."
                  break
                fi
                echo "Waiting for SSM agent... attempt $i/10"
                sleep 10
              done

              # Final status check
              if ! systemctl is-active --quiet snap.amazon-ssm-agent.amazon-ssm-agent.service; then
                  echo "✗ SSM Agent failed to start after multiple attempts."
                  # Optionally tail logs for debugging
                  journalctl -u snap.amazon-ssm-agent.amazon-ssm-agent.service | tail -n 50
                  exit 1 # Exit with an error if it fails to start
              fi
              
              echo "SSM Agent successfully installed and running."
              
              # Install utilities
              echo "Installing utilities..."
              apt-get install -y git wget unzip jq curl
              
              # AWS CLI is already installed at the beginning of the script
              echo "AWS CLI already installed: $(aws --version)"
              
              # Install Java (OpenJDK 11)
              echo "Installing Java..."
              apt-get install -y openjdk-11-jdk
              
              # Install Docker
              echo "Installing Docker..."
              apt-get install -y apt-transport-https ca-certificates software-properties-common
              
              # Add Docker's official GPG key with retries
              mkdir -p /etc/apt/keyrings
              for i in {1..3}; do
                if curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; then
                  break
                fi
                echo "Failed to download Docker GPG key, retrying... attempt $i/3"
                sleep 5
              done
              
              # Add Docker repository
              echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
              
              # Update and install Docker with retries
              apt-get update -y
              for i in {1..3}; do
                if apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
                  break
                fi
                echo "Docker installation failed, retrying... attempt $i/3"
                sleep 10
              done
              
              # Make sure Docker service is enabled and started
              echo "Enabling and starting Docker service..."
              systemctl enable docker
              systemctl start docker
              
              # Wait for Docker to be fully ready
              for i in {1..10}; do
                if docker version >/dev/null 2>&1; then
                  echo "✓ Docker is ready."
                  break
                fi
                echo "Waiting for Docker daemon... attempt $i/10"
                sleep 5
              done
              
              # Verify Docker is installed and running
              if ! docker --version; then
                echo "ERROR: Docker installation failed!"
                exit 1
              fi
              echo "Docker installed successfully: $(docker --version)"
              
              if ! systemctl is-active --quiet docker; then
                echo "ERROR: Docker service is not running!"
                exit 1
              fi
              
              # Add ubuntu user to docker group
              usermod -aG docker ubuntu
              
              # Also add ssm-user to docker group if it exists
              if id "ssm-user" &>/dev/null; then
                  usermod -aG docker ssm-user
                  echo "Added ssm-user to docker group"
              fi
              
              # Also ensure docker commands are in PATH
              echo 'export PATH="/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:$PATH"' >> /etc/profile.d/docker.sh
              chmod +x /etc/profile.d/docker.sh
              
              # Install Jenkins
              echo "Installing Jenkins..."
              curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | tee /usr/share/keyrings/jenkins-keyring.asc > /dev/null
              echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/ | tee /etc/apt/sources.list.d/jenkins.list > /dev/null
              apt-get update -y
              apt-get install -y jenkins
              
              # Configure Jenkins
              echo "Configuring Jenkins..."
              mkdir -p /var/lib/jenkins/init.groovy.d
              
              # Add jenkins user to docker group
              usermod -aG docker jenkins
              
              # Create initial admin user setup script
              cat > /var/lib/jenkins/init.groovy.d/basic-security.groovy << 'GROOVY'
              #!groovy
              import jenkins.model.*
              import hudson.security.*
              import jenkins.install.InstallState
              
              def instance = Jenkins.getInstance()
              
              // Disable setup wizard
              instance.setInstallState(InstallState.INITIAL_SETUP_COMPLETED)
              
              // Create admin user
              def hudsonRealm = new HudsonPrivateSecurityRealm(false)
              hudsonRealm.createAccount('admin', 'admin123')
              instance.setSecurityRealm(hudsonRealm)
              
              def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
              strategy.setAllowAnonymousRead(false)
              instance.setAuthorizationStrategy(strategy)
              
              instance.save()
              GROOVY
              
              # Set proper permissions for Jenkins files
              chown -R jenkins:jenkins /var/lib/jenkins
              chmod 700 /var/lib/jenkins/init.groovy.d/basic-security.groovy
              
              # Start Jenkins
              echo "Starting Jenkins service..."
              systemctl enable jenkins
              systemctl start jenkins
              
              # Wait for Jenkins to start up
              echo "Waiting for Jenkins to start..."
              timeout 300 bash -c 'until curl -s -f http://localhost:8080 > /dev/null; do sleep 5; done'
              
              # Install Jenkins plugins
              echo "Installing Jenkins plugins..."
              JENKINS_CLI="/var/cache/jenkins/war/WEB-INF/jenkins-cli.jar"
              
              # Wait for jenkins-cli.jar to become available (with timeout)
              echo "Waiting for jenkins-cli.jar to become available..."
              COUNTER=0
              while [ $COUNTER -lt 30 ] && [ ! -f $JENKINS_CLI ]; do
                sleep 10
                COUNTER=$((COUNTER+1))
                echo "Waiting for jenkins-cli.jar... attempt $COUNTER/30"
              done
              
              if [ -f $JENKINS_CLI ]; then
                echo "Installing required plugins..."
                JENKINS_HOST="http://localhost:8080"
                JENKINS_CRUMB=$(curl -s "$JENKINS_HOST/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)")
                
                java -jar $JENKINS_CLI -s $JENKINS_HOST -auth admin:admin123 install-plugin \
                  workflow-aggregator \
                  git \
                  docker-workflow \
                  amazon-ecr \
                  aws-credentials \
                  pipeline-aws \
                  ssh-agent
                
                # Restart Jenkins after plugin installation
                java -jar $JENKINS_CLI -s $JENKINS_HOST -auth admin:admin123 safe-restart
              else
                echo "Warning: jenkins-cli.jar not found, skipping plugin installation"
              fi
              
              # Create directories for Cortex XDR installation
              echo "Creating directories for Cortex XDR installation..."
              mkdir -p /etc/panw
              mkdir -p /var/log
              touch /var/log/xdr_install.log
              chmod 666 /var/log/xdr_install.log
              
              # Final verification
              echo "=== Final System Status ===" >> /tmp/user-data-complete.txt
              echo "Docker version: $(docker --version 2>&1)" >> /tmp/user-data-complete.txt
              echo "AWS CLI version: $(aws --version 2>&1)" >> /tmp/user-data-complete.txt
              echo "Docker service: $(systemctl is-active docker)" >> /tmp/user-data-complete.txt
              echo "SSM Agent service: $(systemctl is-active snap.amazon-ssm-agent.amazon-ssm-agent.service)" >> /tmp/user-data-complete.txt
              
              # Create a marker file for deployment readiness
              touch /tmp/deployment-ready
              
              echo "Jenkins installation and configuration completed!"
              EOF

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    tags = merge(var.common_tags, {
      Name = "${var.project_name}-jenkins-volume"
    })
  }
}
# RDS subnet group
resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "${var.project_name}-db-subnet-group"
  subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-db-subnet-group"
  })
}

# RDS instance
resource "aws_db_instance" "hrgoat_db" {
  identifier             = "${var.project_name}-db"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = var.db_instance_class
  allocated_storage      = 20
  storage_type           = "gp2"
  username               = "admin"
  password               = var.db_password
  parameter_group_name   = "default.mysql8.0"
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  publicly_accessible    = true
  skip_final_snapshot    = true
  backup_retention_period = 0
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-db"
  })
}

# ECR repository
resource "aws_ecr_repository" "app_repository" {
  name = "${var.project_name}-app-repository"
  force_delete = true
  
  tags = var.common_tags
}

# Application Load Balancer (ALB)
resource "aws_lb" "app_alb" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  
  enable_deletion_protection = false
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-alb"
  })
}

# ALB Security Group
resource "aws_security_group" "alb_sg" {
  name        = "${var.project_name}-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-alb-sg"
  })
}

# Update App Security Group to allow traffic from ALB
resource "aws_security_group_rule" "app_from_alb" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb_sg.id
  security_group_id        = aws_security_group.app_sg.id
  description              = "Allow traffic from ALB to App"
}

# ALB Target Group
resource "aws_lb_target_group" "app_tg" {
  name     = "${var.project_name}-app-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
  
  health_check {
    enabled             = true
    interval            = 30
    path                = "/"
    port                = "traffic-port"
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200"
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-app-tg"
  })
}

# ALB Listener
resource "aws_lb_listener" "app_listener" {
  load_balancer_arn = aws_lb.app_alb.arn
  port              = 80
  protocol          = "HTTP"
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

# ALB Target Group Attachment
resource "aws_lb_target_group_attachment" "app_attachment" {
  target_group_arn = aws_lb_target_group.app_tg.arn
  target_id        = aws_instance.app_instance.id
  port             = 80
} 
