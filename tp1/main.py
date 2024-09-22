import logging
import time
import urllib.request
import uuid
import os
import paramiko
from datetime import datetime, timedelta

import boto3
from alive_progress import alive_bar
from rich.console import Console


from instance import EC2InstanceWrapper
from keypair import KeyPairWrapper
from security_group import SecurityGroupWrapper
from load_balancer import ElasticLoadBalancerWrapper
from cloudwatch import CloudWatchWrapper

logger = logging.getLogger(__name__)
console = Console()


AWS_ACCESS_KEY_ID='ASIAYGD4W2IMUUQPOZHD'
AWS_SECRET_ACCESS_KEY='UDESjrR+QWQOfqjhbY/fSVvsU86MXjoEQwc6JvOA'
AWS_SESSION_TOKEN='IQoJb3JpZ2luX2VjEHYaCXVzLXdlc3QtMiJHMEUCIQCuHZYVaN9nhszk/GmauhEziF/btLqt8Vj/3UIrTsXrRgIgQWtxazU7fsaHKyZucC5sPUEe2AKf2wZCLStmjozAMssquwIIr///////////ARAAGgw1NjI5MDIyNTgyMDEiDKZ8kYy0tgbSpp836CqPAlQim/hqr7mdpXv2D/BT0VjKXHi+Akla1v7pTk/tVn0ENO72corXHfzPdf0A1f3d/XldzXalnBDkyHKWpS9hpDJZNr0lV2lFNMYbKYbnm7kCfPDOn7x/uZq43y+M3be3tOt81/0Bz2Vuf0fm75h+3np5G0WS3Eftx5wpvK7mH6E3KBJ0FvbktLePtsXgIjfWAEpREGs7esxWcnF7T4SVQO+/cgZpJ5rYHpifgH1Ltiq19vLdHttxj+J7X3Zomge0WBSQm0+a68/H923Oi9534H7/m7r2mq/GxuOx6d4813shYcAOPMJ9amh3gEt34rO2HZTNhJ41M/ORFeznXtm5/2ZWbV7Bzd4Vz87F67/WrrcwmqXCtwY6nQFwPHkRosgF7zow8osrQIy3EmMiKyi4Vd0UXrJ9tnSx7mW1SoqFWK8Ogl/GlyVWzqzgne1+XpEdXNy3K/7o9N//Fip+7JCjSEAfvNk2kvEH/KwnS/T7pDV7y1vC4rbe/DC8g5O2Nlg5YzR0uE/y3I+obIHsYz08PhARcyyV/r6NsQz6zwg513FRUFnRzUactuzGpNU0dvtX3pe491d1'

# TODO: S'assurer que les intances sont bien configurées
INSTANCE_AMI = 'ami-0e54eba7c51c234f6' # Amazon Linux 2 AMI
INSTANCE_COUNT_1 = 1 # 10 requis
INSTANCE_COUNT_2 = 1 # 10 requis
INSTANCE_TYPE_1 = 't2.micro'
INSTANCE_TYPE_2 = 't2.large'

ELB_LISTERNER_PORT_1 = 80
ELB_LISTERNER_PORT_2 = 81

os.environ['INSTANCE_AMI'] = INSTANCE_AMI
os.environ['INSTANCE_COUNT_1'] = str(INSTANCE_COUNT_1)
os.environ['INSTANCE_COUNT_2'] = str(INSTANCE_COUNT_2)
os.environ['INSTANCE_TYPE_1'] = INSTANCE_TYPE_1
os.environ['INSTANCE_TYPE_2'] = INSTANCE_TYPE_2

# TODO: déplacer les var ci-bas dans le fichier de configuration ~/.aws/config et enlever leur référence dans le code
os.environ['AWS_DEFAULT_REGION'] = "us-east-1"
os.environ['AWS_ACCESS_KEY_ID'] = AWS_ACCESS_KEY_ID
os.environ['AWS_SECRET_ACCESS_KEY'] = AWS_SECRET_ACCESS_KEY
os.environ['AWS_SESSION_TOKEN'] = AWS_SESSION_TOKEN

console = Console()

class EC2InstanceScenario:
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
        Initializes the EC2InstanceScenario with the necessary AWS service wrappers.

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

        # Create the key pair and simulate the process with a progress bar.
        with alive_bar(1, title="Creating Key Pair") as bar:
            self.key_wrapper.create(key_name)
            time.sleep(0.4)  # Simulate the delay in key creation
            bar()

        console.print(f"- **Private Key Saved to**: {self.key_wrapper.key_file_path}\n")

        # List key pairs (simulated) and show a progress bar.
        list_keys = True
        if list_keys:
            console.print("- Listing your key pairs...")
            start_time = time.time()
            with alive_bar(100, title="Listing Key Pairs") as bar:
                while time.time() - start_time < 2:
                    time.sleep(0.2)
                    bar(10)
                self.key_wrapper.list(5)
                if time.time() - start_time > 2:
                    console.print(
                        "Taking longer than expected! Please wait...",
                        style="bold yellow",
                    )

    def create_security_group(self, name=f"MySecurityGroup-{uuid.uuid4().hex[:8]}", ) -> None:
        """
        Creates a security group that controls access to the EC2 instance and adds a rule
        to allow SSH access from the user's current public IP address.
        """
        console.print("**Step 2: Create a Security Group : {name}**", style="bold cyan")

        # Create the security group and simulate the process with a progress bar.
        with alive_bar(1, title="Creating Security Group") as bar:
            self.sg_wrapper.create(
                name, "Instances security"
            )
            time.sleep(0.5)
            bar()

        console.print(f"- **Security Group ID**: {self.sg_wrapper.security_group}\n")

        # Get the current public IP to set up SSH access.
        ip_response = urllib.request.urlopen("http://checkip.amazonaws.com")
        current_ip_address = ip_response.read().decode("utf-8").strip()
        console.print(
            "Let's add a rule to allow SSH only from your current IP address."
        )
        console.print(f"- **Your Public IP Address**: {current_ip_address}")
        console.print("- Automatically adding SSH rule...")

        # Update security group rules to allow SSH and simulate with a progress bar.
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

    def creat_security_groups(self) -> None:
        """
        Creates a security group for the EC2 instance and another security group for the load balancer.
        """

        console.print("\n**Step 2: Create Security Groups**", style="bold cyan")

        # Create a security group for the EC2 instance
        console.print("Creating a security group for the EC2 instance...")
        instance_sg_name = f"Instance_SG-{uuid.uuid4().hex[:8]}"
        instance_sg_id = self.sg_wrapper.create(instance_sg_name, "Security group for EC2 instances")

        # Create a security group for the load balancer
        console.print("Creating a security group for the load balancer...")
        lb_sg_name = f"LoadBlancer_SG-{uuid.uuid4().hex[:8]}"
        lb_sg_id = self.sg_wrapper.create(lb_sg_name, "Security group for the load balancer")

        # Get the current public IP to set up SSH access.
        ip_response = urllib.request.urlopen("http://checkip.amazonaws.com")
        current_ip_address = ip_response.read().decode("utf-8").strip()
        console.print(
            "Add a rule to allow SSH only from your current IP address to the security group for the load balancer."
        )

        # Update security group rules to allow SSH and simulate with a progress bar.
        with alive_bar(1, title="Updating Security Group Rules") as bar:
            elb_ip_permissions = [
                    {
                        # SSH ingress open to only the specified IP address.
                        "IpProtocol": "tcp",
                        "FromPort": 80,
                        "ToPort": 80,
                        "IpRanges": [{"CidrIp": f"{ip_response}/32"}],
                    },
                    {
                    # Web server ingress open to the specified IP address.
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": f"{ip_response}/32"}],
                    }
                ]
            
            response = self.sg_wrapper.authorize_ingress(current_ip_address, elb_ip_permissions)
                                          

    def create_instance(self, instance_type) -> None:
        """
        Launches an EC2 instance using an specific AMI and the created key pair
        and security group. Displays instance details and SSH connection information.
        """
        # Retrieve Amazon Linux 2 AMIs from SSM.
        # ami_paginator = self.ssm_client.get_paginator("get_parameters_by_path")
        # ami_options = []
        # for page in ami_paginator.paginate(Path="/aws/service/ami-amazon-linux-latest"):
        #     ami_options += page["Parameters"]
        # amzn2_images = self.inst_wrapper.get_images(
        #     [opt["Value"] for opt in ami_options if "amzn2" in opt["Name"]]
        # )
        console.print("\n**Step 3: Launch Your Instance**", style="bold cyan")
        console.print(
            "Let's create an instance from a specified AMI: {}".format(INSTANCE_AMI)
        )

        # Display instance types compatible with the specified AMI
        inst_types = self.inst_wrapper.get_instance_types("x86_64")  # Adjust architecture as needed

        # Check if the requested instance type is available.
        inst_type_choice = None
        for inst_type in inst_types:
            if inst_type["InstanceType"] == instance_type:
                console.print(f"- Found requested instance type: {inst_type['InstanceType']}")
                inst_type_choice = inst_type
                break
        
        if inst_type_choice is None:
            console.print(f"- Requested instance type '{instance_type}' not found.")
            return

        console.print(
            f"- Selected instance type: {inst_type_choice['InstanceType']}\n"
        )

        console.print("Creating your instance and waiting for it to start...")
        with alive_bar(1, title="Creating Instance") as bar:
            self.inst_wrapper.create(
                INSTANCE_AMI,
                inst_type_choice["InstanceType"],
                self.key_wrapper.key_pair["KeyName"],
                [self.sg_wrapper.security_group],
            )
            time.sleep(1)
            bar()

        console.print(f"**Success! Your instance is ready:**\n", style="bold green")
        self.inst_wrapper.display()

        console.print(
            "You can use SSH to oncnect to your instance. "
            "If the connection attempt times out, you might have to manually update "
            "the SSH ingress rule for your IP address in the AWS Management Console."
        )
        self._display_ssh_info()

    def create_instances_group(self, count, instance_type) -> None:
        """
        Create multiple instances at once
        """
        
        for i in range(count):
            self.create_instance(instance_type)
        
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
        console.print("\n**Step x: Deploy FastAPI Application**", style="bold cyan")
        public_ip = self.get_public_ip(instance_id)
        scp_command = "scp -i " + self.key_wrapper.key_file_path + " -o StrictHostKeyChecking=no -r ./FastAPI ec2-user@" + public_ip + ":~/"
        print(scp_command)
        os.system(scp_command) #TODO: I wasn't able to make it work with sftp paramiko, but should be done with ssm too
        deploy_flask_commands = [
            "sudo yum update && sudo yum upgrade -y",
            "sudo yum install python3 python3-pip -y",
            "pip3 install Flask fastapi uvicorn",
            "chmod +x FastAPI/main.py",
            f"INSTANCE_ID={instance_id} python3 FastAPI/main.py > output.log 2>&1 &"
        ]
        public_ip = self.get_public_ip(instance_id)
        ssh = paramiko.SSHClient() #TODO: Check if possible to use ssm client instead (seems to be blocked)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # local_file_path = "./FastAPI/main.py"
        # remote_file_path = ""
        try:
            ssh.connect(
                hostname=public_ip, 
                username="ec2-user",
                key_filename=self.key_wrapper.key_file_path
            )
            # send ./FastAPI/main.py to the instance
            
            # sftp = ssh.open_sftp()
            # print(f"Uploading {local_file_path} to {remote_file_path}")
            # sftp.put(local_file_path, remote_file_path)
            # print("File upload complete")
            # sftp.close()
            
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

    def monitor_cluster_performance(self, instance_ids, instance_type):
        """
        Monitor the performance of the EC2 instances in the cluster by retrieving
        CPU utilization metrics from CloudWatch.
        """
        start_time = datetime.now() - timedelta(minutes=20)
        end_time = datetime.now()
        print(f"Performance Metrics for {instance_type} instances:")
        for instance_id in instance_ids:
            # Get CPU Utilization statistics
            stats = self.cloudwatch_wrapper.get_metric_statistics(
                namespace='AWS/EC2',
                name='CPUUtilization',
                start=start_time,
                end=end_time,
                period=60,  # intervals
                stat_types=['Average']
            )
            
            # Display the metrics
            for data_point in stats['Datapoints']:
                print(f"Instance ID: {instance_id}, Timestamp: {data_point['Timestamp']}, CPU Utilization: {data_point['Average']}")

    def create_target_group(self, name, protocol, port, vpc_id, target_type) -> dict:
        try:
            response = self.elbv2_client.create_target_group(
                Name=name,
                Protocol=protocol,
                Port=port,
                VpcId=vpc_id,
                HealthCheckProtocol='HTTP',
                HealthCheckPort='8000',
                HealthCheckPath='/',
                TargetType=target_type
                )
            target_group = response['TargetGroups'][0]
            console.print(f"Created target group: {target_group['TargetGroupArn']}")
            return target_group
        except Exception as e:
            console.print(f"An error occurred while creating target group: {str(e)}", style="bold red")
  
    def create_load_balancer(self) -> None:
        """
        Creates a load balancer that distributes incoming traffic across multiple targets.
        """
        # Get VPC
        vpc_id = self.inst_wrapper.instances[0]["VpcId"]

        console.print("\n**Step 5: Create a Load Balancer**", style="bold cyan")
        console.print("Creating a load balancer to distribute incoming traffic...")

        # Create a load balancer and simulate the process with a progress bar.
        with alive_bar(1, title="Creating Load Balancer") as bar:
            subnets = self.get_subnets(vpc_id)
            
            load_balancer_name = f"LoadBalancer-{uuid.uuid4().hex[:8]}"
            elb = self.elb_wrapper.create_load_balancer(
                    load_balancer_name, [subnet["SubnetId"] for subnet in subnets]
                    )

            target_group_1 = self.create_target_group(
                name=f"TargetGroup1-{uuid.uuid4().hex[:8]}", 
                protocol='HTTP', 
                port=8000, 
                vpc_id=vpc_id,
                target_type='instance'
            )
            # Register the instance with the target group
            self.elbv2_client.register_targets(
                TargetGroupArn=target_group_1['TargetGroupArn'],
                Targets=[{'Id': self.inst_wrapper.instances[0]['InstanceId'],
                            'Port': 8000
                            }]
                )
            
            target_group_2 = self.create_target_group(
                name=f"TargetGroup2-{uuid.uuid4().hex[:8]}", 
                protocol='HTTP', 
                port=8000,
                vpc_id=vpc_id,
                target_type='instance'
                )
            
            # Register the instance with the target group
            self.elbv2_client.register_targets(
                TargetGroupArn=target_group_2['TargetGroupArn'],
                Targets=[{'Id': self.inst_wrapper.instances[1]['InstanceId'],
                            'Port': 8000
                            }]
                )

            # Obtain the ARN of the load balancer
            lb_arn = elb['LoadBalancers'][0]['LoadBalancerArn']

            # Create a listener for the load balancer
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

            listener_arn = listener['Listeners'][0].get('ListenerArn')
            if listener_arn is None:
                raise RuntimeError('Listener ARN not found')
            self.elbv2_client.create_rule(
                ListenerArn=listener_arn,
                Conditions=[
                    {'Field': 'path-pattern', 'Values': ['/cluster1', '/cluster1/*']},
                ],
                Priority=1,
                Actions=[
                    {'Type': 'forward', 'TargetGroupArn': target_group_1['TargetGroupArn']},
                ],
            )
            self.elbv2_client.create_rule(
                ListenerArn=listener_arn,
                Conditions=[
                    {'Field': 'path-pattern', 'Values': ['/cluster2', '/cluster2/*']},
                ],
                Priority=2,
                Actions=[
                    {'Type': 'forward', 'TargetGroupArn': target_group_2['TargetGroupArn']},
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

        console.print(f"- **Instances count**: {len(self.inst_wrapper.instances)}")

        for instance in self.inst_wrapper.instances:
            with alive_bar(1, title="Terminating Instance") as bar:
                self.inst_wrapper.terminate()
                time.sleep(1)
                bar()

            console.print("\t- **Terminated Instance with ID: {instance['InstanceId']}**")

        console.print(f"- **Security Group**: {self.sg_wrapper.security_group}")

        with alive_bar(1, title="Deleting Security Group") as bar:
            self.sg_wrapper.delete(self.sg_wrapper.security_group)
            time.sleep(1)
            bar()

        console.print("\t- **Deleted Security Group**")

        console.print(f"- **Key Pair**: {self.key_wrapper.key_pair['KeyName']}")

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
        # self.monitor_cluster_performance([instance["InstanceId"] for instance in self.inst_wrapper.instances], INSTANCE_TYPE_1)
        #self.create_load_balancer()
        
        # TODO: Étapes suivantes
        # self.cleanup()

        console.print("\nThanks for watching!", style="bold green")
        console.print("-" * 88)


if __name__ == "__main__":
    scenario = EC2InstanceScenario(
        EC2InstanceWrapper.from_client(),
        KeyPairWrapper.from_client(),
        SecurityGroupWrapper.from_client(),
        ElasticLoadBalancerWrapper(boto3.client("elbv2")),
        CloudWatchWrapper(boto3.resource("cloudwatch")),
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