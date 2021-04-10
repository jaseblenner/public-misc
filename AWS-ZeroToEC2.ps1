# Begin logging
try {
    $logfilepath = "$(Get-Location)\Afterdeployment-$(get-date -f yyyyMMdd-HHmmss).log"
    Start-Transcript -Path $logfilepath
    Write-Host -ForegroundColor White "Log File began writing to $logfilepath"
}
catch { 
    Write-Host -ForegroundColor Yellow "Warning: Unable to begin writing to log file at $logfilepath"
 }

# Check AWS Modules for PoSH or PoSH Core are installed, if not, install and import
if ($PSEdition -eq "Core") {
    $Modules = (
        "AWSPowerShell.NetCore"
    ) 
}
else {
    $Modules = (
        "AWSPowerShell"    
    )
    # Set Windows proxy credentials as default 
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
foreach ($Module in $Modules) {
    if ((Get-Module -ListAvailable).Name -notcontains "$Module") { 
        try { Install-Module -Name $Module -Force -Confirm:$false -ErrorAction silentlyContinue }
        catch {
            Write-Host -ForegroundColor Red "ERROR: Unable to install $Module - Stopping"
            return
        }
    }
    else {
        Write-Host -ForegroundColor Green "$Module module already installed"
        Import-Module $Module  
    }
}

# Secondly, stipulate AWS paramaters where the environment/application is to be stood up
## Requirement to document - IAM access to AWS ##

# Store AWS access info in global variables
function Store-AWSCredential {

    $global:AWSAccessKeyValue = Read-Host "AWS Access Key"
    $AWSSecretKeyValue = Read-Host -AsSecureString "Enter the AWS Secret Key"
    $global:AWSSecretKeySecure = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AWSSecretKeyValue)
    $global:AWSAccountNameValue = Read-Host "AWS Account Name"

}
Store-AWSCredential

# Set-AWSCredential cmdlet does not scope credentials properly when executed within a function. ref: https://forums.aws.amazon.com/thread.jspa?threadID=259761 
# Authenticate to AWS, set default account & region contexts
Set-AWSCredential -AccessKey $AWSAccessKeyValue -SecretKey $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($AWSSecretKeySecure)).ToString() -StoreAs $AWSAccountNameValue
Set-AWSCredential -StoredCredentials $AWSAccountNameValue
$AWSRegionContextValue = Read-Host 'Enter AWS region context - eg. "ap-southeast-2"'
Initialize-AWSDefaultConfiguration -ProfileName $AWSAccountNameValue -Region $AWSRegionContextValue

# Validate connection to AWS
if ((Get-IAMAccessKey).AccessKeyID -contains "$AWSAccessKeyValue") {
    Write-Host -ForegroundColor Green "Successfully authenticated to AWS account $AWSAccountNameValue as user $AWSAccessKeyValue"
}
else {
    Write-Host -ForegroundColor Red "Failed to authenticate to AWS account $AWSAccountNameValue as user $AWSAccessKeyValue "
    Exit
}

# Deploy new VPC with associated subnet block in AWS account and ensure DNS enabled
Write-Host -ForegroundColor White "Provisioning new VPC...."
$vpc = New-EC2Vpc -CidrBlock $(Read-Host 'Enter CIDR block for new VPC - eg. "10.0.0.0/16"').ToString()
if ($null -ne $vpc.VpcId) {
    while ((Get-EC2Vpc -VpcId $vpc.VpcId).VpcState -ne "available") {
        Write-Host -ForegroundColor Yellow "Waiting for VPC provisioning..."
        Start-Sleep -Seconds 5
    }
    Edit-EC2VpcAttribute -VpcId $vpc.VpcId -EnableDnsSupport $true
    Edit-EC2VpcAttribute -VpcId $vpc.VpcId -EnableDnsHostnames $true
    $vpc = Get-EC2Vpc -VpcId $vpc.VpcId
    Write-Host -ForegroundColor Green "VPC $($vpc.VpcId) provisioned & configured successfully" 
}
else {
    Write-Host -ForegroundColor Red "ERROR: Unable to provision VPC - Stopping"
    return
}

# Deploy an internet gateway, allowing the VPC to route to the internet and attach to VPC
$internetgw = New-EC2InternetGateway
if ($null -ne $internetgw.InternetGatewayId) {
    Write-Host -ForegroundColor Green "Internet gateway $($internetgw.InternetGatewayId) provisioned successfully"
    Add-EC2InternetGateway -InternetGatewayId $internetgw.InternetGatewayId -VpcId $vpc.VpcId
    Write-Host -ForegroundColor Green "Internet gateway $($internetgw.InternetGatewayId) attached to VPC $($vpc.VpcId) successfully"
}
else {
    Write-Host -ForegroundColor Red "ERROR: Unable to provision Internet Gateway - Stopping" 
    return 
}

# Create route table allowing VPC out to internet (ie. via default route)
$routetable = New-EC2RouteTable -VpcId $vpc.VpcId
if ($null -ne $routetable.RouteTableId) {
    Write-Host -ForegroundColor Green "Route Table $($routetable.RouteTableId) provisioned successfully"
    New-EC2Route -RouteTableId $routetable.RouteTableId -GatewayId $internetgw.InternetGatewayId -DestinationCidrBlock '0.0.0.0/0'
    if ((Get-EC2RouteTable -RouteTableId $routetable.RouteTableId).Routes.GatewayId -contains $internetgw.InternetGatewayId) {
        Write-Host -ForegroundColor Green "Default route added to  $($routetable.RouteTableId) successfully" 
    }
}
else {
    Write-Host -ForegroundColor Red "ERROR: Unable to provision route table - Stopping" 
    return 
}

# Provision a subnet within VPC, associate route table with subnet
Write-Host -ForegroundColor White "Provisioning new subnet within VPC..."
$subnet = New-EC2Subnet -VpcId $vpc.VpcId -CidrBlock $(Read-Host 'Enter new CIDRBlock to provision within VPC - eg. "10.0.10.0/24"').ToString() -AvailabilityZone "$($AWSRegionContextValue)a"
if ($null -ne $subnet.subnetID) {
    Write-Host -ForegroundColor Green "Subnet $($subnet.subnetID) provisioned successfully"
    Register-EC2RouteTable -RouteTableId $routetable.RouteTableId -SubnetId $subnet.SubnetId 
}
else {
    Write-Host -ForegroundColor Red "ERROR: Unable to provision subnet - Stopping" 
    return
}

# Create a new key pair for EC2 connectivity
try {
    $EC2KeyPair = New-EC2KeyPair -KeyName "keypair-$($AWSAccountNameValue)"
    $EC2KeyPair | Format-List KeyName, KeyFingerprint
    $EC2KeyPair.KeyMaterial | Out-File -Encoding ascii "$($(Get-Location))/keypair-$($AWSAccountNameValue).pem" -Force
    if ($PSEdition -eq "Core") {
        Write-Host -ForegroundColor White "Protecting key file, enter local workstation user password to take ownership of file"
        sudo chmod 600 "$($(Get-Location))/keypair-$($AWSAccountNameValue).pem"
    }
    Write-Host -ForegroundColor Green "Key pair successfully exported to "$($(Get-Location))/keypair-$($AWSAccountNameValue).pem""
}
catch {
    Write-Host -ForegroundColor Red "Failed to create new keypair within $AWSAccountNameValue"
}


# Spin up a new EC2 instance using an AWS offered Image (AMI) - eg "Amazon Linux AMI 2018.03.0 (HVM), SSD Volume Type - ami-01393ce9a3ca55d67"
try {
    Write-Host -ForegroundColor White "Provisioning new EC2 instance..."
    $tag1 = @{ Key = "Name"; Value = "$(Read-Host 'Enter Instance Name Label - eg. "WEBSERVER"')" }
    $tag2 = @{ Key = "Environment"; Value = "$(Read-Host 'Enter Environment Name Label - eg. "Production"')" }
    $tagspec1 = new-object Amazon.EC2.Model.TagSpecification
    $tagspec1.ResourceType = "instance"
    $tagspec1.Tags.Add($tag1)
    $tagspec1.Tags.Add($tag2)
    
    $ec2instance = New-EC2Instance `
        -InstanceType $(Read-Host 'Enter Instance type - eg. "t2.micro"') `
        -ImageID $(Read-Host 'Enter AMI ID - eg. "ami-01393ce9a3ca55d67"') `
        -SubnetID $subnet.SubnetId `
        -KeyName "keypair-$($AWSAccountNameValue)" `
        -AssociatePublicIp $true `
        -MinCount 1 `
        -MaxCount 1 `
        -TagSpecification $tagspec1 `
        -Verbose
    
    while ((Get-EC2InstanceStatus -InstanceID ($ec2instance).Instances.InstanceId).InstanceState.Name -ne "running") {
        Write-Host -ForegroundColor Yellow "Waiting for EC2 Instance to initialize..."
        Start-Sleep -Seconds 5
    }
    Write-Host -ForegroundColor Green "EC2 Instance $($ec2instance.Instances.InstanceId) started successfully"
}
catch {
    Write-Host -ForegroundColor Red "ERROR: Unable to provision EC2 Instance - Stopping" 
    return
}

# Create custom security group
try { 
    Write-Host -Foregroundcolor White "Provisioning new security group to apply to instance $($ec2instance.Instances.InstanceId)"
    $ec2sg = New-EC2SecurityGroup `
        -GroupName "secgroup-$(($(Get-EC2Instance -InstanceID ($ec2instance).Instances.InstanceId).Instances.Tags | Where-Object Key -eq "Name").Value)" `
        -Description "$(($(Get-EC2Instance -InstanceID ($ec2instance).Instances.InstanceId).Instances.Tags | Where-Object Key -eq "Name").Value) Instance Security Group" `
        -VpcId $vpc.VpcId `
        -Force
    Write-Host -ForegroundColor Green "Created security group $ec2sg"
}
catch {
    Write-Host -ForegroundColor Red "ERROR: Unable to create security group"
    return
}

# Define security group's inbound rules
try {
    Write-Host -Foregroundcolor White "Define security group traffic rules..."
    Grant-EC2SecurityGroupIngress -GroupId $ec2sg -IpPermission @{
        IpProtocol = $(Read-Host 'Enter protocol to grant/deny access against - eg. "tcp"'); 
        FromPort   = $(Read-Host 'Enter start of port range to allow - eg. "80"'); 
        ToPort     = $(Read-Host 'Enter end  of port range to allow - eg. "80"'); 
        IpRanges   = $(Read-Host 'Enter subnet or IP range to allow inbound traffic from - eg. "10.0.0.0/16" or "0.0.0.0/0"')
    }
    Write-Host -ForegroundColor White "Allowing inbound ssh from anywhere. This should be locked down post customization."
    Grant-EC2SecurityGroupIngress -GroupId $ec2sg -IpPermission @{
        IpProtocol = "tcp"; 
        FromPort   = "22"; 
        ToPort     = "22"; 
        IpRanges   = "0.0.0.0/0"
    }
}
catch {
    Write-Host -ForegroundColor Red "ERROR: Unable to apply traffic rules to security group $ec2sg"
    return
}

# Apply security group to instance (ensuring any existing security groups are removed)
try {    
    Edit-EC2InstanceAttribute -InstanceId ($ec2instance).Instances.InstanceId -Attribute "GroupSet" -Value $ec2sg
    Write-Host -ForegroundColor Green "Successfully applied security group $($ec2sg) to instance $(($ec2instance).Instances.InstanceId)"
}
catch {
    Write-Host -ForegroundColor Red "ERROR: Unable to apply traffic security group $($ec2sg) to instance $(($ec2instance).Instances.InstanceId)"
    return
}

# Connect to EC2 instance using SSH, authenticate using newly created private key (stored as PEM)
try {
    $ec2publicip = (Get-EC2Instance -InstanceID $($ec2instance.Instances.InstanceId) | Select -ExpandProperty Instances).PublicIPAddress
    Write-Host -ForegroundColor Yellow "Waiting for SSH to become available.."
    # Wait for EC2 instance to become reachable via SSH
    if ($PSEdition -eq "Core") {
        while ((Test-Connection $ec2publicip -TCPPort 22) -ne "True") {
            Start-Sleep -seconds 2
            Write-Host -ForegroundColor Yellow "Waiting for SSH to become available.."
        }
    }
    else {
        while (((Test-NetConnection $ec2publicip -Port 22).TCPTestSucceeded) -ne "True") {
            Start-Sleep -seconds 2
            Write-Host -ForegroundColor Yellow "Waiting for SSH to become available.."
        }
    }
    # SSH to EC2 instance and invoke required OS customizations
    ssh -i  "$($(Get-Location))/keypair-$($AWSAccountNameValue).pem" ec2-user@$ec2publicip -oStrictHostKeyChecking=no "/usr/bin/sudo bash -c '`
    sudo yum update --assumeyes; `
    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1; `
    sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1; `
    sudo yum install ntp --assumeyes; `
    sudo chkconfig ntpd on; `
    sudo yum install telnet telnet-server --assumeyes;  `
    sudo yum install mtr  --assumeyes; `
    sudo yum update --assumeyes; `
    echo 65535 > /proc/sys/fs/file-max; `
    echo fs.file-max=65535 >> /etc/sysctl.conf; `
    ulimit -n 65535'"
    Write-Host -ForegroundColor Green "OS Customized successfully"
}
catch {
    Write-Host -ForegroundColor Red "Unable to SSH to instance and/or complete OS customizations"
}

# Transfer required config files to /tmp/ on instance
foreach ($file in (Get-ChildItem "$($(Get-Location))/transfer" -Recurse)) {
    try {
        $remotepath = "ec2-user@$($ec2publicip):/tmp/$($file.Name)"
        scp -i "$($(Get-Location))/keypair-$($AWSAccountNameValue).pem" $file $remotepath
        Write-Host -ForegroundColor Green "Successfully transferred file $file to $remotepath" 
    }
    catch { 
        Write-Host -ForegroundColor Red "Failed to transfer file $file to instance"
    }
}

# Connect to EC2 instance using SSH, install components required to run web app and bring web app online
try {
    $ec2publicip = (Get-EC2Instance -InstanceID $($ec2instance.Instances.InstanceId) | Select -ExpandProperty Instances).PublicIPAddress
    Write-Host -ForegroundColor Yellow "Waiting for SSH to become available.."
    # Wait for EC2 instance to become reachable via SSH
    if ($PSEdition -eq "Core") {
        while ((Test-Connection $ec2publicip -TCPPort 22) -ne "True") {
            Start-Sleep -seconds 2
            Write-Host -ForegroundColor Yellow "Waiting for SSH to become available.."
        }
    }
    else {
        while (((Test-NetConnection $ec2publicip -Port 22).TCPTestSucceeded) -ne "True") {
            Start-Sleep -seconds 2
            Write-Host -ForegroundColor Yellow "Waiting for SSH to become available.."
        }
    }
    ssh -i  "$($(Get-Location))/keypair-$($AWSAccountNameValue).pem" ec2-user@$ec2publicip -oStrictHostKeyChecking=no
}
catch {
    Write-Host -ForegroundColor Red "Unable to SSH to instance"
}


# Revoke open SSH access to security group
try {
    Revoke-EC2SecurityGroupIngress -GroupId $ec2sg -IpPermission @{
        IpProtocol = "tcp"; 
        FromPort   = "22"; 
        ToPort     = "22"; 
        IpRanges   = "0.0.0.0/0"
    }
    Write-Host -ForegroundColor Green "Successfully revoked public SSH access to instance"
}
catch {
    Write-Host -ForegroundColor Yellow "Warning: was not able to revoke public SSH access to instance. Please review via EC2 console"
}

Stop-Transcript
