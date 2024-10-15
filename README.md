
# AWS Load Balancing Using Boto3

This repository provides a solution to automate the creation and management of EC2 instances and a custom Load Balancer using AWS services and Boto3. 
The objective is to introduce the concept of Infrastructure as Code and use APIs to create, and deploy a cluster of virtual
machines.

## Assignment Overview

The aim of this project is to:
1. Create EC2 clusters using Elastic Load Balancer (ELB).
2. Benchmark clusters for performance comparison.
3. Develop and deploy a custom network load balancer.
4. Automate the deployment and monitoring of the solution using Infrastructure as Code (IaC).

### Key Components:
- **EC2 Instances**: Create a cluster of EC2 instances (t2.micro and t2.large).
- **Load Balancer**: Implement a custom network load balancer that redirects traffic based on instance performance.
- **CloudWatch**: Use AWS CloudWatch to monitor instance performance and adjust traffic routing dynamically.
- **FastAPI Deployment**: Run a FastAPI application on all EC2 instances to benchmark responses.

## Features

- **Automated EC2 Instance Management**: Spin up EC2 instances using Boto3, assign them to clusters, and manage their lifecycle.
- **Custom Network Load Balancer**: Distribute traffic across EC2 instances based on their response time or CloudWatch metrics.
- **Performance Benchmarking**: Send simultaneous requests to EC2 clusters and measure response times to evaluate performance.
- **Infrastructure as Code**: Automate the entire solution with a single script that creates instances, configures load balancers, deploys the FastAPI app, and runs benchmarks.

## Prerequisites

1. **AWS Account**: You will need an AWS account and credentials with sufficient permissions to create and manage EC2 instances, ELB, and CloudWatch.
2. **Python 3.x**: Install Python and the required libraries (listed in `requirements.txt`).
3. **Boto3**: AWS SDK for Python used to interact with AWS services.
4. **FastAPI**: A simple FastAPI application will be deployed on each EC2 instance for testing purposes.

## Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/marcomudenge/AWS_LoadBalancing_Using_Boto3.git
   cd AWS_LoadBalancing_Using_Boto3
   ```

2. **Create a Virtual Environment and Install Dependencies**:
   ```powershell
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Set up AWS Credentials**:
   Ensure your AWS credentials are set up in the environment using either the AWS CLI or environment variables.

4. **Deploy the Solution**:
   Run the main script that will:
   - Spin up EC2 instances (both t2.micro and t2.large).
   - Configure load balancers.
   - Deploy the FastAPI application.
   - Run benchmarks to measure performance.

   ```Powershell
   ./demo.ps1
   ```

## Assignment Specifications

### EC2 Cluster Setup
- Create **10 EC2 instances**: 5 `t2.micro` and 5 `t2.large`.
- Deploy a **FastAPI application** on each instance that returns a unique identifier for the instance in response to HTTP requests.
- Set up two clusters: one for `t2.micro` instances and another for `t2.large` instances. Traffic for `/cluster1` is routed to the `t2.large` instances, while traffic for `/cluster2` is routed to the `t2.micro` instances.

### Load Balancer
- Develop a network load balancer that:
  - Periodically checks the response times of EC2 instances in the cluster.
  - Routes traffic to the instance with the best performance.
  - Routes traffic to the two clusters according to the requests.
  - Alternatively, use CloudWatch metrics (such as CPU utilization) to dynamically adjust traffic routing.

### Benchmarking
- Send 1000 simultaneous requests to each target group (cluster) and measure response times using Python’s `aiohttp` and `asyncio`.
- Compare the performance between the two clusters.

## Automation
The entire solution should be automated with **Infrastructure as Code**. During the demo, running a simple script should:
- Create and configure EC2 instances.
- Deploy the FastAPI app on each instance.
- Set up the load balancer and monitor performance.
- Run benchmarks automatically.
