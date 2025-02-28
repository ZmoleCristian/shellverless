# HTTPShell

A secure terminal client/server system that provides command-line access to AWS Lambda functions with persistent sessions, background processes, and intelligent Lambda keep-alive functionality.

## Features

- **Terminal-based shell interface** with tab completion, command history, and syntax highlighting
- **Keep-alive mechanism** for AWS Lambda that preserves long-running processes
- **Directory state preservation** to maintain current working directory across Lambda invocations
- **Background process support** with job tracking and management
- **Session management** with unique session IDs for secure multi-user support
- **Smart cleanup** of expired sessions and orphaned processes

## Installation

### Building from source

```bash
# Clone the repository
git clone https://github.com/your-repo/httshell.git
cd httshell

# Build both client and server
./build.sh
```

### Deployment

1. **Lambda Deployment**:
   - Upload `lambda/lambda.zip` to AWS Lambda
   - Configure with API Gateway trigger
   - Set runtime to "Custom runtime on Amazon Linux 2"
   - Set Lambda timeout to maximum (15 minutes)
   - Ensure Lambda has appropriate IAM permissions

2. **Client Usage**:
   ```bash
   ./target/release/httshell-client https://your-lambda-url.lambda-url.region.on.aws/ --keep-alive 300
   ```

## Usage

### Terminal Commands

- Regular shell commands: `ls`, `cd`, `pwd`, etc.
- **!bg \<command>**: Run command in background
- **!ps**: List active background jobs
- **!ka \<seconds>**: Change keep-alive interval
- **exit** or **quit**: Exit the shell

## Architecture

- **Client**: Terminal application with line editing, history, and tab completion
- **Server**: Lambda-optimized shell with session management and background job tracking
- **Keep-alive**: Periodic heartbeats to keep Lambda functions active for as long as needed
- **Job Tracking**: Background processes tracked with unique IDs for reliable management

## Security Considerations

- All sessions use unique identifiers
- Process isolation between different sessions
- Automatic cleanup of expired sessions and processes

## License

[BSD 3-Clause License](LICENSE)

Copyright (c) 2025, Zmole Cristian