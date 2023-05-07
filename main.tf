# Define local variables for instance names
locals {
  instance_names = ["magento", "varnish"]
}

# Configure the AWS provider with the desired region
provider "aws" {
  region = "us-west-2"
}

# Create a VPC with the specified CIDR block
resource "aws_vpc" "this" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "vpc"
  }
}

# Get the available availability zones within the region
data "aws_availability_zones" "available" {
  state = "available"
}

# Create public subnets within the VPC
resource "aws_subnet" "public" {
  for_each = toset(local.instance_names)

  cidr_block        = "10.0.${index(local.instance_names, each.value) + 1}.0/24"
  vpc_id            = aws_vpc.this.id
  availability_zone = data.aws_availability_zones.available.names[index(local.instance_names, each.value)]

  tags = {
    Name = "public-subnet-${index(local.instance_names, each.value) + 1}"
  }
}

# Create an internet gateway and attach it to the VPC
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "internet-gateway"
  }
}

# Create a public route table with a route to the internet gateway
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = {
    Name = "public-route-table"
  }
}

# Create a security group allowing inbound and outbound HTTP, HTTPS and SSH traffic
resource "aws_security_group" "allow_http_https" {
  name        = "allow_http_https"
  description = "Allow inbound and outbound HTTP and HTTPS traffic"
  vpc_id      = aws_vpc.this.id

  # Define outbound rules
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Define inbound rules for HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Define inbound rules for custom port
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Define inbound rules for HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Define inbound rules for SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Associate the public subnets with the public route table
resource "aws_route_table_association" "public" {
  for_each       = toset(local.instance_names)
  subnet_id      = aws_subnet.public[each.value].id
  route_table_id = aws_route_table.public.id
}

# Create a load balancer for the instances
resource "aws_lb" "this" {
  name               = "load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.allow_http_https.id]
  subnets            = values(aws_subnet.public)[*].id
}

# Create an HTTP listener for the load balancer to redirect HTTP to HTTPS
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Generate a TLS private key
resource "tls_private_key" "this" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Create an AWS key pair using the generated public key
resource "aws_key_pair" "this" {
  key_name   = "keypair"
  public_key = tls_private_key.this.public_key_openssh
}

# Output the private key for SSH access (sensitive information)
output "private_key" {
  value       = tls_private_key.this.private_key_pem
  description = "Private key for SSH access"
  sensitive   = true
}

# Create EC2 instances with the specified AMI, instance type, and other configurations
resource "aws_instance" "ubuntu" {
  for_each = toset(local.instance_names)

  ami                    = "ami-01d4b5043e089efa9"
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.this.key_name
  vpc_security_group_ids = [aws_security_group.allow_http_https.id]
  subnet_id              = aws_subnet.public[each.value].id

  associate_public_ip_address = true

  tags = {
    Name = each.key
  }
}

# Create target groups for the instances
resource "aws_lb_target_group" "this" {
  for_each = toset(local.instance_names)

  name     = "${each.key}-target-group"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.this.id

  health_check {
    enabled = true
    path    = "/"
  }
}

# Attach instances to their respective target groups
resource "aws_lb_target_group_attachment" "this" {
  for_each = toset(local.instance_names)

  target_group_arn = aws_lb_target_group.this[each.key].arn
  target_id        = aws_instance.ubuntu[each.key].id
}

# Create an HTTPS listener for the load balancer
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_iam_server_certificate.this.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["varnish"].arn # Use the varnish target group
  }
}

# Create a listener rule to forward specific paths to the magento target group
resource "aws_lb_listener_rule" "media_static" {
  listener_arn = aws_lb_listener.https.arn

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["magento"].arn
  }

  condition {
    path_pattern {
      values = ["/media/*", "/static/*"]
    }
  }
}

# Create a self-signed TLS certificate
resource "tls_self_signed_cert" "this" {
  private_key_pem = tls_private_key.this.private_key_pem

  subject {
    common_name  = "example.com"
    organization = "Example, Inc."
  }

  validity_period_hours = 8760
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]
}

# Attach the self-signed certificate to the HTTPS listener
resource "aws_lb_listener_certificate" "this" {
  listener_arn    = aws_lb_listener.https.arn
  certificate_arn = aws_iam_server_certificate.this.arn
}

# Create a server certificate in IAM using the self-signed certificate
resource "aws_iam_server_certificate" "this" {
  name             = "self-signed-cert"
  certificate_body = tls_self_signed_cert.this.cert_pem
  private_key      = tls_private_key.this.private_key_pem
}


