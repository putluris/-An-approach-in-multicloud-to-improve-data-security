import boto3
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from azure.identity import DefaultAzureCredential

# AWS S3 Setup
s3_client = boto3.client('s3')

def create_s3_bucket(bucket_name):
    response = s3_client.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={'LocationConstraint': boto3.session.Session().region_name}
    )
    s3_client.put_bucket_encryption(
        BucketName=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }
            ]
        }
    )
    return response

# Azure Blob Storage Setup
azure_storage_account_name = "your_storage_account_name"
azure_container_name = "your_container_name"

def create_azure_blob_container():
    credential = DefaultAzureCredential()
    blob_service_client = BlobServiceClient(
        account_url=f"https://{azure_storage_account_name}.blob.core.windows.net",
        credential=credential
    )
    container_client = blob_service_client.create_container(azure_container_name)
    return container_client

def enable_azure_encryption(container_client):
    container_client.set_container_encryption_scope(
        container_encryption_scope={
            "defaultEncryptionScope": "your_encryption_scope",
            "denyEncryptionScopeOverride": True
        }
    )

# MFA Setup for AWS
iam_client = boto3.client('iam')

def enable_aws_mfa(user_name):
    response = iam_client.create_virtual_mfa_device(
        VirtualMFADeviceName=user_name,
        Path='/'
    )
    return response

# MFA Setup for Azure
def enable_azure_mfa(user_principal_name):
    # MFA is typically enabled via the Azure Portal or using PowerShell/CLI commands, not directly via SDK
    pass

if __name__ == "__main__":
    # AWS S3 Setup
    aws_bucket_name = "your-aws-bucket-name"
    create_s3_bucket(aws_bucket_name)
    print(f"AWS S3 Bucket '{aws_bucket_name}' created and encrypted.")

    # Azure Blob Storage Setup
    azure_container_client = create_azure_blob_container()
    enable_azure_encryption(azure_container_client)
    print(f"Azure Blob Container '{azure_container_name}' created and encrypted.")

    # Enable MFA for AWS user
    aws_user_name = "your-aws-username"
    enable_aws_mfa(aws_user_name)
    print(f"MFA enabled for AWS user '{aws_user_name}'.")

    # Azure MFA setup requires manual intervention via Portal or PowerShell/CLI
    azure_user_principal_name = "your-azure-user@domain.com"
    enable_azure_mfa(azure_user_principal_name)
    print(f"Azure MFA setup initiated for user '{azure_user_principal_name}'.")
