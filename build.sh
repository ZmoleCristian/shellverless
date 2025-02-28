#!/bin/bash
set -e

# Ensure rust is installed
if ! command -v rustup &> /dev/null; then
    echo "Rustup not found, please install it"
    exit 1
fi

# Function to print section headers
print_header() {
    echo -e "\n\033[1;34m==== $1 ====\033[0m"
}

# Build the client (default target, GNU)
print_header "Building client binary for GNU target"
cargo build --release --features client --bin httshell-client
echo "Client binary built at target/release/httshell-client"

# Add the musl target
print_header "Setting up MUSL target"
rustup target add x86_64-unknown-linux-musl

# Build the server with MUSL target
print_header "Building server binary with MUSL target"
cargo build --release --features server --no-default-features --bin httshell-server --target x86_64-unknown-linux-musl

# Create the lambda deployment package
print_header "Creating Lambda deployment package"
mkdir -p lambda

# Create bootstrap script
echo '#!/bin/sh' > lambda/bootstrap
echo './httshell-server' >> lambda/bootstrap
chmod +x lambda/bootstrap

# Copy the server binary
cp target/x86_64-unknown-linux-musl/release/httshell-server lambda/

# Create the zip file
cd lambda
print_header "Creating Lambda zip package"
zip -j lambda.zip bootstrap httshell-server
cd ..

print_header "Build Complete"
echo "Client binary: target/release/httshell-client"
echo "Lambda deployment package: lambda/lambda.zip"
echo ""
echo "Usage instructions:"
echo "  1. Upload lambda/lambda.zip to AWS Lambda"
echo "  2. Configure Lambda with API Gateway"
echo "  3. Run the client with your Lambda URL:"
echo "     ./target/release/httshell-client https://your-lambda-url"