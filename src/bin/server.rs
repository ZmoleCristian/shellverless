use lambda_http::{run, service_fn, Body, Error, Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time;

// Global session store to track active sessions
lazy_static::lazy_static! {
    static ref SESSION_STORE: Arc<Mutex<SessionStore>> = Arc::new(Mutex::new(SessionStore::new()));
}

struct SessionStore {
    sessions: std::collections::HashMap<String, Session>,
}

struct Session {
    last_heartbeat: Instant,
    background_jobs: Vec<String>,   // Store job IDs instead of PIDs
    current_dir: String,            // Track current directory
}

impl SessionStore {
    fn new() -> Self {
        SessionStore {
            sessions: std::collections::HashMap::new(),
        }
    }

    fn create_session(&mut self, session_id: &str) {
        self.sessions.insert(session_id.to_string(), Session {
            last_heartbeat: Instant::now(),
            background_jobs: Vec::new(),
            current_dir: "/tmp".to_string(), // Default starting directory
        });
    }

    fn get_session(&mut self, session_id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(session_id)
    }

    fn update_heartbeat(&mut self, session_id: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_heartbeat = Instant::now();
        } else {
            // Create session if it doesn't exist
            self.create_session(session_id);
        }
    }

    fn register_job(&mut self, session_id: &str, job_id: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.background_jobs.push(job_id.to_string());
        }
    }

    fn set_current_dir(&mut self, session_id: &str, dir: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.current_dir = dir.to_string();
        }
    }
    
    fn get_current_dir(&self, session_id: &str) -> String {
        if let Some(session) = self.sessions.get(session_id) {
            session.current_dir.clone()
        } else {
            "/tmp".to_string() // Default
        }
    }
    
    fn cleanup_expired_sessions(&mut self, max_idle_time: Duration) {
        let now = Instant::now();
        let expired: Vec<String> = self.sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.last_heartbeat) > max_idle_time)
            .map(|(id, _)| id.clone())
            .collect();
        
        for session_id in &expired {
            if let Some(session) = self.sessions.get(session_id) {
                // Terminate any background jobs for this session
                for job_id in &session.background_jobs {
                    let _ = Command::new("sh")
                        .args(["-c", &format!("pkill -f \"JOB_ID={}\"", job_id)])
                        .output();
                }
                
                // Clean up job files
                let _ = Command::new("sh")
                    .args(["-c", &format!("rm -f /tmp/job_{}*.log", session_id)])
                    .output();
            }
            self.sessions.remove(session_id);
        }
    }
}

#[derive(Deserialize)]
struct CommandInput {
    command: String,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    background: bool,
}

#[derive(Deserialize)]
struct HeartbeatRequest {
    session_id: String,
    #[serde(default)]
    ttl_seconds: u64,
}

#[derive(Serialize)]
struct CommandOutput {
    output: String,
    status: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
}

#[derive(Serialize)]
struct HeartbeatResponse {
    status: String,
    expires_at: String,
}

// Execute a shell command and return the output
async fn execute_command(cmd: &str, session_id: &str, background: bool) -> Result<CommandOutput, Error> {
    if cmd.trim().is_empty() {
        return Ok(CommandOutput {
            output: "No command provided".to_string(),
            status: 400,
            pid: None,
        });
    }
    
    // Special case for 'cd' command to update the tracked directory
    if cmd.trim().starts_with("cd ") {
        let dir = cmd.trim()[3..].trim();
        
        // No directory means go to home
        let dir = if dir.is_empty() { "/tmp" } else { dir };
        
        // Update the session's current directory
        let mut store = SESSION_STORE.lock().unwrap();
        store.update_heartbeat(session_id);
        
        // Check if directory exists
        let check_cmd = format!("test -d \"{}\" && echo \"exists\" || echo \"not exists\"", 
                               dir.replace("\"", "\\\""));
        let output = Command::new("sh")
            .args(["-c", &check_cmd])
            .output();
            
        if let Ok(output) = output {
            let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if result == "exists" {
                // Directory exists, update session directory
                store.set_current_dir(session_id, dir);
                return Ok(CommandOutput {
                    output: format!("Changed directory to {}", dir),
                    status: 0,
                    pid: None,
                });
            } else {
                return Ok(CommandOutput {
                    output: format!("cd: {}: No such directory", dir),
                    status: 1,
                    pid: None,
                });
            }
        }
    }
    
    // Update heartbeat for this session
    let current_dir = {
        let mut store = SESSION_STORE.lock().unwrap();
        store.update_heartbeat(session_id);
        store.get_current_dir(session_id)
    };
    
    // For background processes
    if background {
        // Generate a unique job ID
        let job_id = uuid::Uuid::new_v4().to_string();
        
        // Make the command run in background with tracking mechanism
        let escaped_cmd = cmd.replace("'", "'\\''"); // Escape single quotes
        let bg_cmd = format!(
            "cd '{}' && nohup sh -c 'export JOB_ID=\"{}\" && {}' > /tmp/job_{}_{}.out 2> /tmp/job_{}_{}.err & echo $!",
            current_dir.replace("'", "'\\''"),
            job_id,
            escaped_cmd,
            session_id,
            job_id,
            session_id,
            job_id
        );
        
        let output = Command::new("sh")
            .args(["-c", &bg_cmd])
            .output();
            
        match output {
            Ok(output) => {
                let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let pid = pid_str.parse::<u32>().ok();
                
                // Register the job with the session
                if !session_id.is_empty() {
                    let mut store = SESSION_STORE.lock().unwrap();
                    store.register_job(session_id, &job_id);
                }
                
                Ok(CommandOutput {
                    output: format!("Process started in background with ID: {}", job_id),
                    status: 0,
                    pid,
                })
            },
            Err(e) => Ok(CommandOutput {
                output: format!("Failed to execute background command: {}", e),
                status: 500,
                pid: None,
            })
        }
    } else {
        // Normal foreground execution
        // Execute command in the session's current directory
        let full_cmd = format!("cd '{}' && {}", 
                             current_dir.replace("'", "'\\''"), 
                             cmd);
        
        let output = Command::new("sh")
            .args(["-c", &full_cmd])
            .output();
        
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
                    pid: None,
                })
            },
            Err(e) => Ok(CommandOutput {
                output: format!("Failed to execute command: {}", e),
                status: 500,
                pid: None,
            })
        }
    }
}

// Function to get status of background jobs
async fn get_background_jobs_status(session_id: &str) -> Result<String, Error> {
    let mut store = SESSION_STORE.lock().unwrap();
    
    if let Some(session) = store.get_session(session_id) {
        if session.background_jobs.is_empty() {
            return Ok("No background jobs running.".to_string());
        }
        
        let job_ids = session.background_jobs.join(" ");
        let cmd = format!(
            "echo 'Active background jobs:' && for job in {}; do
             if ps -ef | grep -v grep | grep \"JOB_ID=$job\" > /dev/null; then
                echo \"  - Job $job: Running\"
                cat /tmp/job_{}_$job.out 2>/dev/null | tail -5 | sed 's/^/    /'
             else
                echo \"  - Job $job: Completed\" 
                cat /tmp/job_{}_$job.out 2>/dev/null | tail -5 | sed 's/^/    /'
             fi
             done",
            job_ids, session_id, session_id
        );
        
        match Command::new("sh").args(["-c", &cmd]).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                if stdout.trim().is_empty() {
                    Ok("No active background jobs found.".to_string())
                } else {
                    Ok(stdout)
                }
            },
            Err(e) => {
                Ok(format!("Error retrieving job status: {}", e))
            }
        }
    } else {
        Ok("No active session found.".to_string())
    }
}

// Handle heartbeat requests to keep the Lambda alive
async fn handle_heartbeat(req: &HeartbeatRequest) -> Result<HeartbeatResponse, Error> {
    let session_id = &req.session_id;
    let ttl_seconds = if req.ttl_seconds > 0 && req.ttl_seconds <= 900 {
        // Cap at 15 minutes (Lambda max)
        req.ttl_seconds
    } else {
        300 // Default 5 minutes
    };
    
    // Update the session's heartbeat
    let mut store = SESSION_STORE.lock().unwrap();
    store.update_heartbeat(session_id);
    
    // Calculate expiration time
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(ttl_seconds as i64);
    
    Ok(HeartbeatResponse {
        status: "active".to_string(),
        expires_at: expires_at.to_rfc3339(),
    })
}

// Start a background task to clean up expired sessions
async fn start_cleanup_task() {
    let cleanup_interval = Duration::from_secs(60); // Check every minute
    let max_idle_time = Duration::from_secs(300); // 5 minutes of inactivity
    
    tokio::spawn(async move {
        let mut interval = time::interval(cleanup_interval);
        loop {
            interval.tick().await;
            let mut store = SESSION_STORE.lock().unwrap();
            store.cleanup_expired_sessions(max_idle_time);
        }
    });
}

// Process API Gateway requests
async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    // Check if this is a direct command invocation
    let path = event.uri().path();
    
    // Special handling for heartbeat endpoint
    if path == "/heartbeat" {
        if let Some(content_type) = event.headers().get("content-type") {
            let content_type = content_type.to_str().unwrap_or("");
            
            if content_type.contains("application/json") {
                if let Ok(heartbeat_req) = serde_json::from_slice::<HeartbeatRequest>(event.body()) {
                    let result = handle_heartbeat(&heartbeat_req).await?;
                    return Ok(Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(serde_json::to_string(&result)?.into())?);
                }
            }
        }
        
        // Invalid heartbeat request
        return Ok(Response::builder()
            .status(400)
            .header("content-type", "application/json")
            .body(r#"{"error":"Invalid heartbeat request"}"#.into())?);
    }
    
    // Handle state checking endpoint
    if path == "/bg-status" {
        if let Some(query) = event.uri().query() {
            let mut session_id = String::new();
            
            // Parse the query parameters
            for param in query.split('&') {
                if param.starts_with("session=") {
                    session_id = param.replace("session=", "");
                    break;
                }
            }
            
            if !session_id.is_empty() {
                // Get the status of background jobs for this session
                let result = get_background_jobs_status(&session_id).await?;
                
                return Ok(Response::builder()
                    .status(200)
                    .header("content-type", "text/plain")
                    .body(result.into())?);
            }
        }
        
        return Ok(Response::builder()
            .status(400)
            .header("content-type", "text/plain")
            .body("Invalid session ID".into())?);
    }
    
    // Handle command execution requests
    
    // Parse the request based on content type
    if let Some(content_type) = event.headers().get("content-type") {
        let content_type = content_type.to_str().unwrap_or("");
        
        if content_type.contains("application/json") {
            // JSON request
            let body = event.body();
            if let Ok(cmd_input) = serde_json::from_slice::<CommandInput>(body) {
                // Get or create session
                let session_id = if cmd_input.session_id.is_empty() {
                    uuid::Uuid::new_v4().to_string()
                } else {
                    cmd_input.session_id.clone()
                };
                
                // Execute the command
                let result = execute_command(
                    &cmd_input.command, 
                    &session_id, 
                    cmd_input.background
                ).await?;
                
                return Ok(Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .header("x-session-id", session_id)
                    .body(serde_json::to_string(&result)?.into())?);
            }
            
            // Try to extract command from generic JSON
            if let Ok(json) = serde_json::from_slice::<Value>(body) {
                if let Some(Value::String(cmd)) = json.get("command").or_else(|| json.get("cmd")) {
                    // Generate a new session ID
                    let session_id = uuid::Uuid::new_v4().to_string();
                    let result = execute_command(cmd, &session_id, false).await?;
                    
                    return Ok(Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .header("x-session-id", session_id)
                        .body(serde_json::to_string(&result)?.into())?);
                }
            }
        } else if content_type.contains("text/plain") {
            // Plain text request (treat body as command)
            let command = String::from_utf8_lossy(event.body()).to_string();
            let session_id = uuid::Uuid::new_v4().to_string();
            let result = execute_command(&command, &session_id, false).await?;
            
            return Ok(Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .header("x-session-id", session_id)
                .body(result.output.into())?);
        }
    }
    
    // Check query parameters for command
    if let Some(params) = event.uri().query() {
        let mut cmd = "";
        let mut session_id = uuid::Uuid::new_v4().to_string();
        let mut background = false;
        
        // Parse query parameters
        for param in params.split('&') {
            if param.starts_with("command=") || param.starts_with("cmd=") {
                cmd = &param[param.find('=').unwrap_or(0) + 1..];
            } else if param.starts_with("session=") {
                session_id = param.replace("session=", "");
            } else if param == "bg=true" || param == "background=true" {
                background = true;
            }
        }
        
        if !cmd.is_empty() {
            let decoded = urlencoding::decode(cmd).unwrap_or(std::borrow::Cow::Borrowed(cmd));
            let result = execute_command(&decoded, &session_id, background).await?;
            
            return Ok(Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .header("x-session-id", session_id)
                .body(serde_json::to_string(&result)?.into())?);
        }
    }
    
    // If we've made it here, extract command from path
    if path.len() > 1 {
        // Remove leading slash and decode URL
        let cmd = &path[1..];
        let decoded = urlencoding::decode(cmd).unwrap_or(std::borrow::Cow::Borrowed(cmd));
        let session_id = uuid::Uuid::new_v4().to_string();
        let result = execute_command(&decoded, &session_id, false).await?;
        
        Ok(Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .header("x-session-id", session_id)
            .body(result.output.into())?)
    } else {
        // No command found
        Ok(Response::builder()
            .status(400)
            .header("content-type", "text/plain")
            .body("Please provide a command to execute.\n\nYou can:\n1. Send a POST with JSON: {\"command\": \"your command\", \"session_id\": \"optional_id\", \"background\": false}\n2. Use query parameter: ?command=your+command&session=your_session&bg=true\n3. Use the path: /your+command\n4. Keep-alive: Send heartbeats to /heartbeat with {\"session_id\": \"your_id\", \"ttl_seconds\": 300}\n".into())?)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Start the session cleanup task
    start_cleanup_task().await;
    
    // Log startup
    println!("Starting HTTPShell Lambda with session management and keep-alive support");
    
    // Start the Lambda runtime
    run(service_fn(function_handler)).await?;
    Ok(())
}