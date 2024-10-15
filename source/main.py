import asyncio
import logging
import time
import urllib.request
import uuid
import os
import paramiko
from datetime import datetime, timedelta, timezone
import pandas as pd

import boto3
from alive_progress import alive_bar
from rich.console import Console


from instance import EC2InstanceWrapper
from keypair import KeyPairWrapper
from security_group import SecurityGroupWrapper
from load_balancer import ElasticLoadBalancerWrapper
from cloudwatch import CloudWatchWrapper
import benchmark as bm

logger = logging.getLogger(__name__)
console = Console()

# Read AWS credentials from environment file AWSaccess.txt
with open("AWS_access.txt", "r") as file:
    AWS_ACCESS_KEY_ID = file.readline().split("aws_access_key_id=")[1].strip()
    AWS_SECRET_ACCESS_KEY = file.readline().split("aws_secret_access_key=")[1].strip()
    AWS_SESSION_TOKEN = file.readline().split("aws_session_token=")[1].strip()

# Verify that the AWS credentials are set
if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY or not AWS_SESSION_TOKEN:
    console.print(
        "AWS credentials not found. Please ensure that the 'AWSaccess.txt' file contains the necessary credentials.",
        style="bold red",
    )
    exit(1)

INSTANCE_AMI = 'ami-0e54eba7c51c234f6' # Amazon Linux 2 AMI
INSTANCE_COUNT_1 = 5 #t2.micro
INSTANCE_COUNT_2 = 4 #t2.large
INSTANCE_TYPE_1 = 't2.micro'
INSTANCE_TYPE_2 = 't2.large'

os.environ['INSTANCE_AMI'] = INSTANCE_AMI
os.environ['INSTANCE_COUNT_1'] = str(INSTANCE_COUNT_1)
os.environ['INSTANCE_COUNT_2'] = str(INSTANCE_COUNT_2)
os.environ['INSTANCE_TYPE_1'] = INSTANCE_TYPE_1
os.environ['INSTANCE_TYPE_2'] = INSTANCE_TYPE_2

os.environ['AWS_DEFAULT_REGION'] = "us-east-1"
os.environ['AWS_ACCESS_KEY_ID'] = AWS_ACCESS_KEY_ID
os.environ['AWS_SECRET_ACCESS_KEY'] = AWS_SECRET_ACCESS_KEY
os.environ['AWS_SESSION_TOKEN'] = AWS_SESSION_TOKEN

console = Console()

class ELBScenario:
    """
    A scenario that demonstrates how to use Boto3 to manage Amazon EC2 resources.
    Covers creating a key pair, security group, launching an instance, associating
    an Elastic IP, and cleaning up resources.
    """

    def __init__(
        self,
        inst_wrapper: EC2InstanceWrapper,
        key_wrapper: KeyPairWrapper,
        sg_wrapper: SecurityGroupWrapper,
        elb_wrapper: ElasticLoadBalancerWrapper,
        cloudwatch_wrapper: CloudWatchWrapper,
        ssm_client: boto3.client,
        elbv2_client: boto3.client,
        remote_exec: bool = False
    ):
        """
        Initializes the ELBScenario with the necessary AWS service wrappers.

        :param inst_wrapper: Wrapper for EC2 instance operations.
        :param key_wrapper: Wrapper for key pair operations.
        :param sg_wrapper: Wrapper for security group operations.
        :param eip_wrapper: Wrapper for Elastic IP operations.
        :param ssm_client: Boto3 client for accessing SSM to retrieve AMIs.
        :param remote_exec: Flag to indicate if the scenario is running in a remote execution
                            environment. Defaults to False. If True, the script won't prompt
                            for user interaction.
        """
        self.inst_wrapper = inst_wrapper
        self.key_wrapper = key_wrapper
        self.sg_wrapper = sg_wrapper
        self.elb_wrapper = elb_wrapper
        self.cloudwatch_wrapper = cloudwatch_wrapper
        self.ssm_client = ssm_client
        self.remote_exec = remote_exec
        self.elbv2_client = elbv2_client

    def create_and_list_key_pairs(self) -> None:
        """
        Creates an RSA key pair for SSH access to the EC2 instance and lists available key pairs.
        """
        console.print("**Step 1: Create a Secure Key Pair**", style="bold cyan")
        console.print(
            "Let's create a secure RSA key pair for connecting to your EC2 instance."
        )
        key_name = f"MyUniqueKeyPair-{uuid.uuid4().hex[:8]}"
        console.print(f"- **Key Pair Name**: {key_name}")

        with alive_bar(1, title="Creating Key Pair") as bar:
            self.key_wrapper.create(key_name)
            time.sleep(0.4) 
            bar()

        console.print(f"- **Private Key Saved to**: {self.key_wrapper.key_file_path}\n")

    def create_security_group(self, name=f"MySecurityGroup-{uuid.uuid4().hex[:8]}", ) -> None:
        """
        Creates a security group that controls access to the EC2 instance and adds a rule
        to allow SSH access from the user's current public IP address.
        """
        console.print("**Step 2: Create a Security Group : {name}**", style="bold cyan")

        with alive_bar(1, title="Creating Security Group") as bar:
            self.sg_wrapper.create(
                name, "Instances security"
            )
            time.sleep(0.5)
            bar()

        console.print(f"- **Security Group ID**: {self.sg_wrapper.security_group}\n")

        ip_response = urllib.request.urlopen("http://checkip.amazonaws.com")
        current_ip_address = ip_response.read().decode("utf-8").strip()
        console.print(
            "Let's add a rule to allow SSH only from your current IP address."
        )
        console.print(f"- **Your Public IP Address**: {current_ip_address}")
        console.print("- Automatically adding SSH rule...")

        with alive_bar(1, title="Updating Security Group Rules") as bar:
            response = self.sg_wrapper.authorize_ingress(current_ip_address)
            time.sleep(0.4)
            if response and response.get("Return"):
                console.print("- **Security Group Rules Updated**.")
            else:
                console.print(
                    "- **Error**: Couldn't update security group rules.",
                    style="bold red",
                )
            bar()

        self.sg_wrapper.describe(self.sg_wrapper.security_group)                                      

    def create_instance(self, inst_type_choice) -> None:
        """
        Launches an EC2 instance using an specific AMI and the created key pair
        and security group. Displays instance details and SSH connection information.
        """
        console.print("Creating an instance now...")

        with alive_bar(1, title="Creating Instances") as bar:
            self.inst_wrapper.create(
                INSTANCE_AMI,
                inst_type_choice["InstanceType"],
                self.key_wrapper.key_pair["KeyName"],
                [self.sg_wrapper.security_group],
            )
            time.sleep(1)
            bar()     

        self.inst_wrapper.display()

        self._display_ssh_info()

    def create_instances_group(self, count, instance_type) -> None:
        """
        Create multiple instances at once
        """
        console.print("\n**Step 3: Launch Your Instance**", style="bold cyan")
        console.print(
            "Let's create {} instance from a specified AMI: {} and instance type : {}".format(count, INSTANCE_AMI, instance_type)
        )

        inst_types = self.inst_wrapper.get_instance_types("x86_64")

        inst_type_choice = None
        for inst_type in inst_types:
            if inst_type["InstanceType"] == instance_type:
                console.print(f"- Found requested instance type: {inst_type['InstanceType']}")
                inst_type_choice = inst_type
                break
        
        if inst_type_choice is None:
            console.print(f"- Requested instance type '{instance_type}' not found.")
            return
        
        for i in range(count):
            self.create_instance(inst_type_choice)     

        
    def _display_ssh_info(self) -> None:
        """
        Displays SSH connection information for the user to connect to the EC2 instance.
        Handles the case where the instance does or does not have an associated public IP address.
        """
        if self.inst_wrapper.instances:
            instance = self.inst_wrapper.instances[0]
            instance_id = instance["InstanceId"]

            waiter = self.inst_wrapper.ec2_client.get_waiter("instance_running")
            console.print(
                "Waiting for the instance to be in a running state with a public IP...",
                style="bold cyan",
            )

            with alive_bar(1, title="Waiting for Instance to Start") as bar:
                waiter.wait(InstanceIds=[instance_id])
                time.sleep(1)
                bar()

            public_ip = self.get_public_ip(instance_id)
            if public_ip:
                console.print(
                    "\nTo connect via SSH, open another command prompt and run the following command:",
                    style="bold cyan",
                )
                console.print(
                    f"\tssh -i {self.key_wrapper.key_file_path} ec2-user@{public_ip}"
                )
            else:
                console.print(
                    "Instance does not have a public IP address assigned.",
                    style="bold red",
                )
        else:
            console.print(
                "No instance available to retrieve public IP address.",
                style="bold red",
            )
        
    def get_public_ip(self, instance_id):
        instance = self.inst_wrapper.ec2_client.describe_instances(
            InstanceIds=[instance_id]
            )["Reservations"][0]["Instances"][0]
        return instance.get("PublicIpAddress")

    def deploy_flask_fastapi(self, instance_id):
        """
        Deploys a FastAPI application to the EC2 instance by sending the files over SCP
        and running the necessary commands to install dependencies and start the server.
        """
        console.print(f"\n**Deploy FastAPI Application on instance {instance_id}**", style="bold cyan")
        public_ip = self.get_public_ip(instance_id)
        scp_command = "scp -i " + self.key_wrapper.key_file_path + " -o StrictHostKeyChecking=no -r ./FastAPI ec2-user@" + public_ip + ":~/"
        print(scp_command)
        os.system(scp_command)
        deploy_flask_commands = [
            "sudo yum update && sudo yum upgrade -y",
            "sudo yum install python3 python3-pip -y",
            "pip3 install Flask fastapi uvicorn",
            "chmod +x FastAPI/main.py",
            f"INSTANCE_ID={instance_id} python3 FastAPI/main.py > output.log 2>&1 &"
        ]
        public_ip = self.get_public_ip(instance_id)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=public_ip, 
                username="ec2-user",
                key_filename=self.key_wrapper.key_file_path
            )
            
            for command in deploy_flask_commands:
                print(f"Executing: {command}")
                stdin, stdout, stderr = ssh.exec_command(command)
                exit_status = stdout.channel.recv_exit_status()
                if exit_status == 0:
                    print(f"Command succeeded: {command}")
                else:
                    print(f"Command failed: {command}, Error: {stderr.read().decode()}")
                    break

        except paramiko.SSHException as e:
            print(f"SSH connection failed: {str(e)}")
        
        finally:
            ssh.close()

    def monitor_cluster_performance(self, instance_ids):
        """
        Monitor the performance of the EC2 instances in the cluster by retrieving
        CPU utilization metrics from CloudWatch.
        """
        start_time = datetime.now(tz=timezone.utc) - timedelta(minutes=10)
        end_time = datetime.now(tz=timezone.utc)
        print("Performance Metrics:")
        data = []
        for instance_id in instance_ids:
            instance_data = {}
            stats = self.cloudwatch_wrapper.get_metric_statistics(
                namespace='AWS/EC2',
                name='CPUUtilization',
                instance_id=instance_id,
                start=start_time,
                end=end_time,
                period=60,  # intervals
                stat_types=['Average'],
                unit='Percent',
            )

            instance_data['InstanceID'] = instance_id
            instance_data['data_points'] = []
            for data_point in stats:
                timestamp = data_point['Timestamp'].strftime('%Y-%m-%d %H:%M:%S') 
                instance_data['data_points'].append({
                    # Convert the timestamp to a string
                    timestamp: data_point['Average']
                })
           
            data.append(instance_data)
        
        df = pd.DataFrame(data)
        df.to_csv('performance_metrics.csv', index=False)

    def create_target_group(self, name, protocol, port, vpc_id) -> dict:
        try:
            target_group = self.elb_wrapper.create_target_group(
                target_group_name=name,
                protocol=protocol,
                port=port,
                vpc_id=vpc_id,
                )
            console.print(f"Created target group: {target_group['TargetGroupArn']}")
            return target_group
        except Exception as e:
            console.print(f"An error occurred while creating target group: {str(e)}", style="bold red")
  
    def create_load_balancer(self) -> None:
        """
        Creates a load balancer that distributes incoming traffic across multiple targets.
        """
        vpc_id = self.inst_wrapper.instances[0]["VpcId"]

        console.print("\n**Step 5: Create a Load Balancer**", style="bold cyan")
        console.print("Creating a load balancer to distribute incoming traffic...")

        with alive_bar(1, title="Creating Load Balancer") as bar:
            instance_availability_zones = [inst["Placement"]["AvailabilityZone"] for inst in self.inst_wrapper.instances]
            instance_availability_zones.extend(['us-east-1a', 'us-east-1b'])
            instance_availability_zones = list(set(instance_availability_zones))
            subnets = self.get_subnets(vpc_id, zones=instance_availability_zones)
            
            security_group_id = self.sg_wrapper.security_group

            load_balancer_name = f"LoadBalancer-{uuid.uuid4().hex[:8]}"
            elb = self.elb_wrapper.create_load_balancer(
                    load_balancer_name, [subnet["SubnetId"] for subnet in subnets], [security_group_id]
                    )

            target_group_1 = self.create_target_group(
                name=f"TargetGroup1-{uuid.uuid4().hex[:8]}", 
                protocol='HTTP', 
                port=8000, 
                vpc_id=vpc_id,
            )

            type_1_instances = [instance for instance in self.inst_wrapper.instances if instance["InstanceType"] == INSTANCE_TYPE_1]
            type_2_instances = [instance for instance in self.inst_wrapper.instances if instance["InstanceType"] == INSTANCE_TYPE_2]

            self.elbv2_client.register_targets(
                TargetGroupArn=target_group_1['TargetGroupArn'],
                Targets=[{'Id': i['InstanceId'], 'Port': 8000} for i in type_1_instances]
                )
            
            target_group_2 = self.create_target_group(
                name=f"TargetGroup2-{uuid.uuid4().hex[:8]}", 
                protocol='HTTP', 
                port=8000,
                vpc_id=vpc_id,
                )
            
            self.elbv2_client.register_targets(
                TargetGroupArn=target_group_2['TargetGroupArn'],
                Targets=[{'Id': i['InstanceId'], 'Port': 8000} for i in type_2_instances]
                )

            lb_arn = elb.get('LoadBalancerArn')

            listener = self.elbv2_client.create_listener(
                LoadBalancerArn=lb_arn,
                Protocol='HTTP',
                Port=80,
                DefaultActions=[
                    {
                        "Type": "fixed-response",
                        "FixedResponseConfig": {
                            "StatusCode": "404"
                        }
                    }
                ],
            )

            self.elb_wrapper.listener = listener['Listeners'][0]

            listener_arn = listener['Listeners'][0].get('ListenerArn')
            if listener_arn is None:
                raise RuntimeError('Listener ARN not found')
            
            self.elbv2_client.create_rule(
                ListenerArn=listener_arn,
                Conditions=[
                    {'Field': 'path-pattern', 
                     'Values': ['/cluster1', '/cluster1/*']},
                ],
                Priority=1,
                Actions=[
                    {'Type': 'forward', 
                     'TargetGroupArn': target_group_1['TargetGroupArn']},
                ],
            )

            self.elbv2_client.create_rule(
                ListenerArn=listener_arn,
                Conditions=[
                    {'Field': 'path-pattern', 
                     'Values': ['/cluster2', '/cluster2/*']},
                ],
                Priority=2,
                Actions=[
                    {'Type': 'forward',
                     'TargetGroupArn': target_group_2['TargetGroupArn']},
                ],
            )
            
            logging.info("Verifying access to the load balancer endpoint.")
            endpoint = self.elb_wrapper.get_endpoint(load_balancer_name)
            lb_success = self.elb_wrapper.verify_load_balancer_endpoint(endpoint)
            if lb_success:
                logging.info("Load balancer endpoint is accessible.")
            else:
                logging.error("Load balancer endpoint is not accessible.")
            time.sleep(1)
            bar()
        
    def register_targets(self, target_group_arn: str, instance_id: str) -> None:
        """
        Registers an instance as a target with the specified target group.

        :param target_group_arn: The ARN of the target group to register the instance with.
        :param instance_id: The ID of the instance to register as a target.
        """
        try:
            response = self.elb_wrapper.elb_client.register_targets(target_group_arn, [instance_id])
            if response and response.get("ResponseMetadata"):
                console.print(
                    f"Instance {instance_id} registered as a target with target group {target_group_arn}."
                )
            else:
                console.print(
                    f"Failed to register instance {instance_id} with target group {target_group_arn}.",
                    style="bold red",
                )
        except:
            console.print(
                f"An error occurred while registering instance {instance_id} with target group {target_group_arn}.",
                style="bold red")
            
    
    def get_subnets(self, vpc_id: str, zones: list[str] = ['us-east-1b', 'us-east-1a']) -> list[dict[str, any]]:
        """
        Gets the default subnets in a VPC for a specified list of Availability Zones.

        :param vpc_id: The ID of the VPC to look up.
        :param zones: The list of Availability Zones to look up.
        :return: The list of subnets found.
        """
        # Ensure that 'zones' is a list, even if None is passed
        if zones is None:
            zones = []
        try:
            client = boto3.client("ec2")
            paginator = client.get_paginator("describe_subnets")
            page_iterator = paginator.paginate(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "availability-zone", "Values": zones},
                    {"Name": "default-for-az", "Values": ["true"]},
                ]
            )

            subnets = []
            for page in page_iterator:
                subnets.extend(page["Subnets"])

            console.print(f"Found {len(subnets)} subnets for the specified zones.")
            return subnets
        except:
            console.print("An error occurred while retrieving subnets.", style="bold red")
            return []

    def cleanup(self) -> None:
        """
        Cleans up all the resources created during the scenario, including disassociating
        and releasing the Elastic IP, terminating the instance, deleting the security
        group, and deleting the key pair.
        """
        console.print("\n**Step 6: Clean Up Resources**", style="bold cyan")
        console.print("Cleaning up resources:")
        
        console.print("- **Listeners**")
        if self.elb_wrapper.listener:
            with alive_bar(1, title="Deleting Load Balancer") as bar:
                self.elb_wrapper.delete_listener(self.elb_wrapper.listener["ListenerArn"])
                time.sleep(0.4)
                bar()
        
        if self.elb_wrapper.load_balancer:
            console.print(f"- **Load Balancer**: {self.elb_wrapper.load_balancer['LoadBalancerName']}")
            with alive_bar(1, title="Deleting Load Balancer") as bar:
                self.elb_wrapper.delete_load_balancer(self.elb_wrapper.load_balancer["LoadBalancerName"])
                time.sleep(0.4)
                bar()
            
        console.print("\t- **Deleted Load Balancer**")
        
        console.print("- **Target Groups**")
        if self.elb_wrapper.target_groups:
            with alive_bar(1, title="Deleting Target Groups") as bar:
                for target_group in self.elb_wrapper.target_groups:
                    self.elb_wrapper.delete_target_group(target_group["TargetGroupName"])
                time.sleep(0.4)
                bar()

        console.print(f"- **Instances count**: {len(self.inst_wrapper.instances)}")
        if self.inst_wrapper.instances:
            with alive_bar(1, title="Terminating Instance") as bar:
                self.inst_wrapper.terminate()
                time.sleep(1)
                bar()

        console.print("\t- **Terminated Instance with ID: {instance['InstanceId']}**")

        console.print(f"- **Security Group**: {self.sg_wrapper.security_group}")
        if self.sg_wrapper.security_group:
            with alive_bar(1, title="Deleting Security Group") as bar:
                self.sg_wrapper.delete(self.sg_wrapper.security_group)
                time.sleep(1)
                bar()

        console.print("\t- **Deleted Security Group**")

        console.print(f"- **Key Pair**: {self.key_wrapper.key_pair['KeyName']}")
        if self.key_wrapper.key_pair:
            with alive_bar(1, title="Deleting Key Pair") as bar:
                self.key_wrapper.delete(self.key_wrapper.key_pair["KeyName"])
                time.sleep(0.4)
                bar()

        console.print("\t- **Deleted Key Pair**")
        
    def run_scenario(self) -> None:
        """
        Executes the entire EC2 instance scenario: creates key pairs, security groups,
        launches an instance and cleans up all resources.
        """
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

        console.print("-" * 88)
        console.print(
            "Welcome to the Amazon Elastic Compute Cloud (Amazon EC2) get started with instances demo.",
            style="bold magenta",
        )
        console.print("-" * 88)
        # Create load balancer
        
        self.create_and_list_key_pairs()
        self.create_security_group()
        self.create_instances_group(INSTANCE_COUNT_1, INSTANCE_TYPE_1)
        self.create_instances_group(INSTANCE_COUNT_2, INSTANCE_TYPE_2)
        for instance in self.inst_wrapper.instances:
            self.deploy_flask_fastapi(instance["InstanceId"])
        self.create_load_balancer()
        input("Press Enter to start benchmark...")
        lb_dns = self.elb_wrapper.load_balancer["DNSName"]
        console.print(f"Starting benchmark with load balancer DNS: {lb_dns}")
        asyncio.run(bm.main(lb_dns))
        input("Press Enter to view performances...")
        self.monitor_cluster_performance([instance["InstanceId"] for instance in self.inst_wrapper.instances])

        console.print("\nThanks for watching!", style="bold green")
        console.print("-" * 88)


if __name__ == "__main__":
    scenario = ELBScenario(
        EC2InstanceWrapper.from_client(),
        KeyPairWrapper.from_client(),
        SecurityGroupWrapper.from_client(),
        ElasticLoadBalancerWrapper(boto3.client("elbv2")),
        CloudWatchWrapper(boto3.client("cloudwatch")),
        boto3.client("ssm"),
        boto3.client("elbv2"),
        remote_exec=False
    )
    try:
        scenario.run_scenario()
        input("Press Enter to continue...")
    except Exception:
        logging.exception("Something went wrong with the demo.")
    scenario.cleanup()