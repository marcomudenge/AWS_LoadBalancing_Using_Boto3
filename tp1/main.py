import logging
import time
import urllib.request
import uuid
import os
import paramiko

import boto3
from alive_progress import alive_bar
from rich.console import Console


from instance import EC2InstanceWrapper
from keypair import KeyPairWrapper
from security_group import SecurityGroupWrapper
from elastic_ip import ElasticIpWrapper
from load_balancer import ElasticLoadBalancerWrapper

logger = logging.getLogger(__name__)
console = Console()

AWS_ACCESS_KEY_ID = 'ASIAYGD4W2IMTTDIQR3P'
AWS_SECRET_ACCESS_KEY = '0IQoPhoiEmrbLsMJ2zqrgCZ85KXZ1JZYRiKVL1ju'
AWS_SESSION_TOKEN ='IQoJb3JpZ2luX2VjEFUaCXVzLXdlc3QtMiJHMEUCIQCkCbU1RAj2us4WSc48xbRkWIUg5fsWzUrlLaywoZ1zywIgR4dOs7cfhBid+bBcF/eSYskoxIVdx56DkV2PNHkUTOkquwIIjv//////////ARAAGgw1NjI5MDIyNTgyMDEiDIU0uiytXFG/S+LvniqPAjp2Em89fR04guJT3OOCKAAeOGXTK+cACjHd9HptJL5Yt7TPhUyaVVUI3HMl6tP2y4KtacjSpRpU/NKZ0D8LczsthQYdDZVZ0UwnWgGMVurjb3tYEAeiMTqoE4m8ag+IPjSsxInO4G7qaoL/QuH0fqjhTSJTSvZX/zSSO7PUriQRFco3KI1PqUQR+dXB5XjZIg59JBrWv0XGw1xpydhIGDZSxhhbPGz75/Jc9xgMqosQ+IAcQS3KyZpYaBYAYoYNgmu0eFFRUCbsR4TOpgNNZV+mOpfkIYcUaDLNwt+wAuxfLGgYYU9hFsxgBv7JGZoDthN506WzmArnxArlogEicMBUG7wvCWekoUNCfq/8PckwqYS7twY6nQGzLCmrSKUk/PpZaJgBW9ylilS5+snwWQNlNn7s11VqDokm3brw0a6DpwvRCqQdMHCpXITHVBsyc5io4W/x/WganMsUmg+EAviZ68/EtghF1U66nfFBLmerY6QSawZ1m57DaUvU3b6wUWjfCV3Fr9FO2IaJgnQie3eqxUrbrzUo+y6DBg/nBk1CbJbd9mrNsQA2Ef4fG1dEpQYQQgQM'


# TODO: S'assurer que les intances sont bien configurées
INSTANCE_AMI = 'ami-0e54eba7c51c234f6' # Amazon Linux 2 AMI
INSTANCE_COUNT_1 = 1 # 10 requis
INSTANCE_COUNT_2 = 1 # 10 requis
INSTANCE_TYPE_1 = 't2.micro'
INSTANCE_TYPE_2 = 't2.small'

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
        eip_wrapper: ElasticIpWrapper,
        elb_wrapper: ElasticLoadBalancerWrapper,
        ssm_client: boto3.client,
        remote_exec: bool = False,
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
        self.eip_wrapper = eip_wrapper
        self.elb_wrapper = elb_wrapper
        self.ssm_client = ssm_client
        self.remote_exec = remote_exec

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

    def create_security_group(self) -> None:
        """
        Creates a security group that controls access to the EC2 instance and adds a rule
        to allow SSH access from the user's current public IP address.
        """
        console.print("**Step 2: Create a Security Group**", style="bold cyan")
        console.print(
            "Security groups manage access to your instance. Let's create one."
        )
        sg_name = f"MySecurityGroup-{uuid.uuid4().hex[:8]}"
        console.print(f"- **Security Group Name**: {sg_name}")

        # Create the security group and simulate the process with a progress bar.
        with alive_bar(1, title="Creating Security Group") as bar:
            self.sg_wrapper.create(
                sg_name, "Security group for example: get started with instances."
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

    def create_instance(self, instance_type) -> None:
        """
        Launches an EC2 instance using an Amazon Linux 2 AMI and the created key pair
        and security group. Displays instance details and SSH connection information.
        """
        # Retrieve Amazon Linux 2 AMIs from SSM.
        ami_paginator = self.ssm_client.get_paginator("get_parameters_by_path")
        ami_options = []
        for page in ami_paginator.paginate(Path="/aws/service/ami-amazon-linux-latest"):
            ami_options += page["Parameters"]
        amzn2_images = self.inst_wrapper.get_images(
            [opt["Value"] for opt in ami_options if "amzn2" in opt["Name"]]
        )
        console.print("\n**Step 3: Launch Your Instance**", style="bold cyan")
        console.print(
            "Let's create an instance from an Amazon Linux 2 AMI. Here are some options:"
        )

        # Check if the requested AMI is available.
        image_choice = 0
        if instance_type:
            for i, image in enumerate(amzn2_images):
                if image["ImageId"] == instance_type:
                    console.print(f"- Found requested AMI: {image['ImageId']}")
                    image_choice = i
                    break
        
        console.print(f"- Selected AMI: {amzn2_images[image_choice]['ImageId']}\n")

        # Display instance types compatible with the selected AMI
        inst_types = self.inst_wrapper.get_instance_types(
            amzn2_images[image_choice]["Architecture"]
        )
        
        # Check if the requested instance type is available.
        inst_type_choice = 0
        if instance_type:
            for i, inst_type in enumerate(inst_types):
                if inst_type["InstanceType"] == instance_type:
                    console.print(f"- Found requested instance type: {inst_type['InstanceType']}")
                    inst_type_choice = i
                    break
        
        console.print(
            f"- Selected instance type: {inst_types[inst_type_choice]['InstanceType']}\n"
        )

        console.print("Creating your instance and waiting for it to start...")
        with alive_bar(1, title="Creating Instance") as bar:
            self.inst_wrapper.create(
                amzn2_images[image_choice]["ImageId"],
                inst_types[inst_type_choice]["InstanceType"],
                self.key_wrapper.key_pair["KeyName"],
                [self.sg_wrapper.security_group],
            )
            time.sleep(21)
            bar()

        console.print(f"**Success! Your instance is ready:**\n", style="bold green")
        self.inst_wrapper.display()

        console.print(
            "You can use SSH to oncnect to your instance. "
            "If the connection attempt times out, you might have to manually update "
            "the SSH ingress rule for your IP address in the AWS Management Console."
        )
        self._display_ssh_info()

    def create_instances_group(self, count: 2, instance_type) -> None:
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
        """ if (
            not self.eip_wrapper.elastic_ips
            or not self.eip_wrapper.elastic_ips[0].allocation_id
        ):
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
                    time.sleep(20)
                    bar()

                instance = self.inst_wrapper.ec2_client.describe_instances(
                    InstanceIds=[instance_id]
                )["Reservations"][0]["Instances"][0]

                public_ip = instance.get("PublicIpAddress")
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
        else:
            elastic_ip = self.eip_wrapper.elastic_ips[0]
            elastic_ip_address = elastic_ip.public_ip
            console.print(
                f"\tssh -i {self.key_wrapper.key_file_path} ec2-user@{elastic_ip_address}"
            ) """
            

        # if not self.remote_exec:
        #     console.print("\nOpen a new terminal tab to try the above SSH command.")
        #     input("Press Enter to continue...")

        """ def associate_elastic_ip(self) -> None:
        """
        # Allocates an Elastic IP address and associates it with the EC2 instance.
        # Displays the Elastic IP address and SSH connection information.
        """
        console.print("\n**Step 4: Allocate an Elastic IP Address**", style="bold cyan")
        console.print(
            "You can allocate an Elastic IP address and associate it with your instance\n"
            "to keep a consistent IP address even when your instance restarts."
        )

        with alive_bar(1, title="Allocating Elastic IP") as bar:
            elastic_ip = self.eip_wrapper.allocate()
            time.sleep(0.5)
            bar()

        console.print(
            f"- **Allocated Static Elastic IP Address**: {elastic_ip.public_ip}."
        )

        with alive_bar(1, title="Associating Elastic IP") as bar:
            self.eip_wrapper.associate(
                elastic_ip.allocation_id, self.inst_wrapper.instances[0]["InstanceId"]
            )
            time.sleep(2)
            bar()

        console.print(f"- **Associated Elastic IP with Your Instance**.")
        console.print(
            "You can now use SSH to connect to your instance by using the Elastic IP."
        )
        self._display_ssh_info() """

    def stop_and_start_instance(self) -> None:
        """
        Stops and restarts the EC2 instance. Displays instance state and explains
        changes that occur when the instance is restarted,
        """
        console.print("\n**Step 5: Stop and Start Your Instance**", style="bold cyan")
        console.print("Let's stop and start your instance to see what changes.")
        console.print("- **Stopping your instance and waiting until it's stopped...**")

        with alive_bar(1, title="Stopping Instance") as bar:
            self.inst_wrapper.stop()
            time.sleep(360)
            bar()

        console.print("- **Your instance is stopped. Restarting...**")

        with alive_bar(1, title="Starting Instance") as bar:
            self.inst_wrapper.start()
            time.sleep(20)
            bar()

        console.print("**Your instance is running.**", style="bold green")
        self.inst_wrapper.display()

        """ elastic_ip = (
            self.eip_wrapper.elastic_ips[0] if self.eip_wrapper.elastic_ips else None
        )

        if elastic_ip is None or elastic_ip.allocation_id is None:
            console.print(
                "- **Note**: Every time your instance is restarted, its public IP address changes."
            )
        else:
            console.print(
                f"Because you have associated an Elastic IP with your instance, you can \n"
                f"connect by using a consistent IP address after the instance restarts: {elastic_ip.public_ip}"
            ) """

        self._display_ssh_info()
        
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
            "python3 FastAPI/main.py"
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

    def create_load_balancer(self) -> None:
        """
        Creates a load balancer that distributes incoming traffic across multiple targets.
        """
        # Get VPC
        vpc_id = self.inst_wrapper.instances[0]["VpcId"]

        # Create two target groups for the load balancer.
        target_group_1 = self.elb_wrapper.create_target_group(target_group_name = f"TargetGroup1-{uuid.uuid4().hex[:8]}", protocol='HTTP', port=80, vpc_id=vpc_id)

        console.print("\n**Step 5: Create a Load Balancer**", style="bold cyan")
        console.print("Creating a load balancer to distribute incoming traffic...")

        # Create a load balancer and simulate the process with a progress bar.
        with alive_bar(1, title="Creating Load Balancer") as bar:
            self.elb_wrapper.create(self.sg_wrapper.security_group)
            time.sleep(1)
            bar()

        console.print(f"- **Load Balancer Name**: {self.elb_wrapper.load_balancer['LoadBalancerName']}")
        console.print(f"- **DNS Name**: {self.elb_wrapper.load_balancer['DNSName']}")

        console.print("\n**Load Balancer Configuration**:")
        console.print(f"- **Security Group**: {self.sg_wrapper.security_group}")
        console.print(f"- **Subnets**: {self.elb_wrapper.load_balancer['AvailabilityZones']}")

        console.print("\n**Load Balancer Listener Configuration**:")
        console.print(
            f"- **Protocol**: {self.elb_wrapper.listener['Protocol']}\n"
            f"- **Port**: {self.elb_wrapper.listener['LoadBalancerPort']}\n"
            f"- **Instance Protocol**: {self.elb_wrapper.listener['InstanceProtocol']}\n"
            f"- **Instance Port**: {self.elb_wrapper.listener['InstancePort']}"
        )

        """ console.print("\n**Load Balancer Health Check Configuration**:")
        console.print(
            f"- **Target**: {self.elb_wrapper.health_check['Target']}\n"
            f"- **Interval**: {self.elb_wrapper.health_check['Interval']} seconds\n"
            f"- **Timeout**: {self.elb_wrapper.health_check['Timeout']} seconds\n"
            f"- **Healthy Threshold**: {self.elb_wrapper.health_check['HealthyThreshold']}\n"
            f"- **Unhealthy Threshold**: {self.elb_wrapper.health_check['UnhealthyThreshold']}"
        )

        console.print("\n**Load Balancer Attributes**:")
        console.print(
            f"- **Cross-Zone Load Balancing**: {self.elb_wrapper.attributes['CrossZoneLoadBalancing']}\n"
            f"- **Connection Draining**: {self.elb_wrapper.attributes['ConnectionDraining']}\n"
            f"- **Connection Draining Timeout**: {self.elb_wrapper.attributes['ConnectionDrainingTimeout']}" """

    def cleanup(self) -> None:
        """
        Cleans up all the resources created during the scenario, including disassociating
        and releasing the Elastic IP, terminating the instance, deleting the security
        group, and deleting the key pair.
        """
        console.print("\n**Step 6: Clean Up Resources**", style="bold cyan")
        console.print("Cleaning up resources:")

        """         
        for elastic_ip in self.eip_wrapper.elastic_ips:
            console.print(f"- **Elastic IP**: {elastic_ip.public_ip}")

            with alive_bar(1, title="Disassociating Elastic IP") as bar:
                self.eip_wrapper.disassociate(elastic_ip.allocation_id)
                time.sleep(2)
                bar()

            console.print("\t- **Disassociated Elastic IP from the Instance**")

            with alive_bar(1, title="Releasing Elastic IP") as bar:
                self.eip_wrapper.release(elastic_ip.allocation_id)
                time.sleep(1)
                bar()

            console.print("\t- **Released Elastic IP**") """


        console.print(f"- **Instances count**: {len(self.inst_wrapper.instances)}")

        for instance in self.inst_wrapper.instances:
            with alive_bar(1, title="Terminating Instance") as bar:
                self.inst_wrapper.terminate()
                time.sleep(380)
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
        #self.create_instances_group(INSTANCE_COUNT_2, INSTANCE_TYPE_2)
        self.deploy_flask_fastapi(self.inst_wrapper.instances[0]["InstanceId"])
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
        ElasticIpWrapper.from_client(),
        ElasticLoadBalancerWrapper(boto3.client("elbv2")),
        boto3.client("ssm"),
    )
    try:
        scenario.run_scenario()
        input("Press Enter to continue...")
        scenario.cleanup()
    except Exception:
        logging.exception("Something went wrong with the demo.")
        scenario.cleanup()
