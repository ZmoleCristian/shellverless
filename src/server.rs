use lambda_http::{run, service_fn, Body, Error, Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Command;

#[derive(Deserialize)]
struct CommandInput {
    command: String,
}

#[derive(Serialize)]
struct CommandOutput {
    output: String,
    status: i32,
}

// Execute a shell command and return the output
async fn execute_command(cmd: &str) -> Result<CommandOutput, Error> {
    if cmd.trim().is_empty() {
        return Ok(CommandOutput {
            output: "No command provided".to_string(),
            status: 400,
        });
    }
    
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", cmd])
            .output()
    } else {
        Command::new("sh")
            .args(["-c", cmd])
            .output()
    };
    
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            
            let result = if !stdout.is_empty() {
                stdout
            } else if !stderr.is_empty() {
                stderr
            } else {
                "Command executed successfully (no output)".to_string()
            };
            
            Ok(CommandOutput {
                output: result,
                status: output.status.code().unwrap_or(0),
            })
        },
        Err(e) => Ok(CommandOutput {
            output: format!("Failed to execute command: {}", e),
            status: 500,
        })
    }
}

// Process API Gateway requests
async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    // Check if this is a direct command invocation
    let path = event.uri().path();
    
    // Parse the request based on content type
    if let Some(content_type) = event.headers().get("content-type") {
        let content_type = content_type.to_str().unwrap_or("");
        
        if content_type.contains("application/json") {
            // JSON request
            let body = event.body();
            if let Ok(cmd_input) = serde_json::from_slice::<CommandInput>(body) {
                // Execute the command
                let result = execute_command(&cmd_input.command).await?;
                return Ok(Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(serde_json::to_string(&result)?.into())?);
            }
            
            // Try to extract command from generic JSON
            if let Ok(json) = serde_json::from_slice::<Value>(body) {
                if let Some(Value::String(cmd)) = json.get("command").or_else(|| json.get("cmd")) {
                    let result = execute_command(cmd).await?;
                    return Ok(Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(serde_json::to_string(&result)?.into())?);
                }
            }
        } else if content_type.contains("text/plain") {
            // Plain text request (treat body as command)
            let command = String::from_utf8_lossy(event.body()).to_string();
            let result = execute_command(&command).await?;
            return Ok(Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .body(result.output.into())?);
        }
    }
    
    // Check query parameters for command
    if let Some(params) = event.uri().query() {
        if params.starts_with("command=") || params.starts_with("cmd=") {
            let cmd = params.replace("command=", "").replace("cmd=", "");
            let decoded = urlencoding::decode(&cmd).unwrap_or(std::borrow::Cow::Borrowed(&cmd));
            let result = execute_command(&decoded).await?;
            
            return Ok(Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .body(result.output.into())?);
        }
    }
    
    // If we've made it here, extract command from path
    if path.len() > 1 {
        // Remove leading slash and decode URL
        let cmd = &path[1..];
        let decoded = urlencoding::decode(cmd).unwrap_or(std::borrow::Cow::Borrowed(cmd));
        let result = execute_command(&decoded).await?;
        
        Ok(Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(result.output.into())?)
    } else {
        // No command found
        Ok(Response::builder()
            .status(400)
            .header("content-type", "text/plain")
            .body("Please provide a command to execute.\n\nYou can:\n1. Send a POST with JSON: {\"command\": \"your command\"}\n2. Use query parameter: ?command=your+command\n3. Use the path: /your+command\n".into())?)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Start the Lambda runtime
    run(service_fn(function_handler)).await?;
    Ok(())
}
