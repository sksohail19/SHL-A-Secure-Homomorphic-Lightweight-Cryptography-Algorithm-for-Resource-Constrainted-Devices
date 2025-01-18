provide "aws" {
    region = "us-east-1"
}

resource "aws_instance" "shl_servevr" {
    ami = "ami-0c02fb55956c7d316"
    instance_type = "t2.micro"
    key_name = var.key_name

    tags = {
        Name = "SHL-Server"
    }

    provisioner "remote-exec" {
        inline = [
            "sudo yum install -y docker",
            "sudo systemctl start docker",
            "sudo systemctl enable docker",
        ]
    }
}

output "server_ip" {
    value = aws_instance.shl_server.public_ip
}