use colored::Colorize;
use reqwest::Client;
use rustyline::error::ReadlineError;
use rustyline::{CompletionType, Config, EditMode, Editor, Helper};
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::validate::Validator;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use std::collections::HashSet;
use std::env;
use std::process::exit;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct CommandRequest {
    command: String,
    session_id: String,
    background: bool,
}

#[derive(Deserialize, Debug)]
struct CommandResponse {
    output: String,
    status: i32,
    #[serde(default)]
    pid: Option<u32>,
}

#[derive(Serialize)]
struct HeartbeatRequest {
    session_id: String,
    ttl_seconds: u64,
}

#[derive(Deserialize, Debug)]
struct HeartbeatResponse {
    #[allow(dead_code)]
    status: String,
    #[allow(dead_code)]
    expires_at: String,
}

struct ClientState {
    session_id: String,
    server_url: String,
    background_processes: Vec<u32>,
    keep_alive_seconds: u64,
    is_running: Arc<AtomicBool>,
}

struct ShellCompleter {
    filename_completer: FilenameCompleter,
    command_completer: HashSet<String>,
}

impl ShellCompleter {
    fn new() -> Self {
        let mut commands = HashSet::new();
        
        for cmd in ["ls", "cd", "pwd", "cat", "grep", "find", "ps", "echo", "mkdir", 
                   "rm", "cp", "mv", "touch", "less", "head", "tail", "wc", "sort",
                   "uniq", "cut", "sed", "awk", "tr", "df", "du", "free", "top",
                   "exit", "quit", "!ps", "!bg", "!ka", "help", "uname", "whoami",
                   "date", "curl", "wget", "ping", "ssh", "scp", "tar", "gzip", "gunzip"] {
            commands.insert(cmd.to_string());
        }
        
        Self {
            filename_completer: FilenameCompleter::new(),
            command_completer: commands,
        }
    }
}

impl Completer for ShellCompleter {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, ctx: &rustyline::Context<'_>) 
        -> rustyline::Result<(usize, Vec<Pair>)> {
        
        if line.starts_with("!") {
            let special_cmd = &line[1..pos];
            let special_cmds = ["bg ", "ps", "ka "];
            
            let matches = special_cmds.iter()
                .filter(|&&cmd| cmd.starts_with(special_cmd))
                .map(|&cmd| Pair { 
                    display: format!("!{}", cmd), 
                    replacement: format!("!{}", cmd) 
                })
                .collect::<Vec<_>>();
            
            if !matches.is_empty() {
                return Ok((1, matches));
            }
            
            if line.starts_with("!bg ") {
                let (pos, mut completions) = self.filename_completer.complete(line, pos, ctx)?;
                for pair in &mut completions {
                    pair.replacement = format!("!bg {}", pair.replacement.trim_start_matches("!bg "));
                }
                return Ok((pos, completions));
            }
        }
        
        if !line.contains(' ') {
            let matches: Vec<Pair> = self.command_completer.iter()
                .filter(|cmd| cmd.starts_with(line))
                .map(|cmd| Pair { 
                    display: cmd.clone(), 
                    replacement: cmd.clone() 
                })
                .collect();
            
            if !matches.is_empty() {
                return Ok((0, matches));
            }
        }
        
        self.filename_completer.complete(line, pos, ctx)
    }
}

impl Highlighter for ShellCompleter {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> std::borrow::Cow<'l, str> {
        std::borrow::Cow::Borrowed(line)
    }

    fn highlight_char(&self, _line: &str, _pos: usize) -> bool {
        false
    }
}

impl Hinter for ShellCompleter {
    type Hint = String;
    
    fn hint(&self, _line: &str, _pos: usize, _ctx: &rustyline::Context<'_>) -> Option<Self::Hint> {
        None
    }
}

impl Validator for ShellCompleter {}

impl Helper for ShellCompleter {}

// Start a background heartbeat task
async fn start_heartbeat_task(
    client: Client,
    state: Arc<Mutex<ClientState>>,
) {
    let is_running = {
        let state = state.lock().await;
        state.is_running.clone()
    };
    
    tokio::spawn(async move {
        while is_running.load(Ordering::SeqCst) {
            // Get current state
            let heartbeat_req = {
                let state = state.lock().await;
                HeartbeatRequest {
                    session_id: state.session_id.clone(),
                    ttl_seconds: state.keep_alive_seconds,
                }
            };
            
            // Determine the server URL
            let heartbeat_url = {
                let state = state.lock().await;
                format!("{}heartbeat", state.server_url)
            };
            
            // Send the heartbeat
            let _ = client.post(&heartbeat_url)
                .json(&heartbeat_req)
                .send()
                .await;
            
            // Sleep for half the TTL to ensure we refresh before expiration
            let sleep_duration = {
                let state = state.lock().await;
                Duration::from_secs(state.keep_alive_seconds / 2)
            };
            
            tokio::time::sleep(sleep_duration).await;
        }
    });
}

// Check the status of background processes
async fn check_background_processes(
    client: &Client,
    state: &Arc<Mutex<ClientState>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let (server_url, session_id) = {
        let state = state.lock().await;
        (state.server_url.clone(), state.session_id.clone())
    };
    
    let status_url = format!("{}bg-status?session={}", server_url, session_id);
    let response = client.get(&status_url).send().await?;
    
    if response.status().is_success() {
        Ok(response.text().await?)
    } else {
        Ok("Failed to get background process status".to_string())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    let mut server_url = String::new();
    let mut keep_alive_seconds = 300u64;
    let mut i = 1;
    
    while i < args.len() {
        match args[i].as_str() {
            "-k" | "--keep-alive" => {
                if i + 1 < args.len() {
                    if let Ok(ttl) = args[i + 1].parse::<u64>() {
                        keep_alive_seconds = ttl;
                        i += 2;
                        continue;
                    }
                }
                i += 1;
            },
            url if !url.starts_with("-") => {
                server_url = url.to_string();
                i += 1;
            },
            _ => i += 1,
        }
    }
    
    if server_url.is_empty() {
        eprintln!("{}", "Error: Please provide the server URL as an argument.".red());
        eprintln!("Usage: {} <server_url> [--keep-alive <seconds>]", args[0]);
        exit(1);
    }
    
    if !server_url.ends_with('/') {
        server_url = format!("{}/", server_url);
    }
    
    let client = Client::new();
    let session_id = uuid::Uuid::new_v4().to_string();
    
    let state = Arc::new(Mutex::new(ClientState {
        session_id,
        server_url: server_url.clone(),
        background_processes: Vec::new(),
        keep_alive_seconds,
        is_running: Arc::new(AtomicBool::new(true)),
    }));
    
    start_heartbeat_task(client.clone(), state.clone()).await;
    
    println!("{}", "=== HTTPShell Client ===".bright_green());
    println!("{} {}", "Connected to:".yellow(), server_url);
    println!("{} {}", "Session ID:".yellow(), state.lock().await.session_id);
    println!("{} {} seconds", "Keep-alive interval:".yellow(), keep_alive_seconds);
    println!("{}", "Special commands:".bright_blue());
    println!("  !bg <command>    - Run command in background");
    println!("  !ps              - List background processes");
    println!("  !ka <seconds>    - Change keep-alive interval");
    println!("  exit             - Exit the shell");
    println!("");
    
    let config = Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Emacs)
        .build();
    
    let mut rl = Editor::with_config(config)?;
    rl.set_helper(Some(ShellCompleter::new()));
    
    let history_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".httshell_history");
    let _ = rl.load_history(&history_path);
    
    loop {
        let prompt = format!("{} ", "λ>".bright_green());
        let readline = rl.readline(&prompt);
        
        match readline {
            Ok(line) => {
                let line = line.trim();
                
                if line.is_empty() {
                    continue;
                }
                
                let _ = rl.add_history_entry(line);
                
                if line == "exit" || line == "quit" {
                    println!("{}", "Goodbye!".bright_green());
                    state.lock().await.is_running.store(false, Ordering::SeqCst);
                    break;
                } else if line == "!ps" {
                    match check_background_processes(&client, &state).await {
                        Ok(status) => println!("{}", status),
                        Err(e) => eprintln!("{} {}", "Error checking background processes:".red(), e),
                    }
                    continue;
                } else if line.starts_with("!ka ") {
                    if let Ok(seconds) = line[4..].trim().parse::<u64>() {
                        state.lock().await.keep_alive_seconds = seconds;
                        println!("{} {}", "Keep-alive interval changed to".green(), seconds);
                    } else {
                        eprintln!("{}", "Invalid keep-alive interval".red());
                    }
                    continue;
                }
                
                let (command, background) = if line.starts_with("!bg ") {
                    (line[4..].trim().to_string(), true)
                } else {
                    (line.to_string(), false)
                };
                
                match execute_command(&client, &state, &command, background).await {
                    Ok(response) => {
                        if !response.output.is_empty() {
                            println!("{}", response.output);
                        }
                        
                        if let Some(pid) = response.pid {
                            state.lock().await.background_processes.push(pid);
                        }
                        
                        if response.status != 0 {
                            eprintln!("{} {}", "Command exited with status:".red(), response.status);
                        }
                    }
                    Err(err) => {
                        eprintln!("{} {}", "Error executing command:".red(), err);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("Ctrl+C pressed, press Ctrl+D or type 'exit' to exit");
            }
            Err(ReadlineError::Eof) => {
                println!("{}", "Goodbye!".bright_green());
                state.lock().await.is_running.store(false, Ordering::SeqCst);
                break;
            }
            Err(err) => {
                eprintln!("{} {}", "Error reading line:".red(), err);
                break;
            }
        }
    }
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = rl.save_history(&history_path);
    
    Ok(())
}

async fn execute_command(
    client: &Client,
    state: &Arc<Mutex<ClientState>>,
    command: &str,
    background: bool,
) -> Result<CommandResponse, Box<dyn std::error::Error>> {
    // Get session information
    let (server_url, session_id) = {
        let state = state.lock().await;
        (state.server_url.clone(), state.session_id.clone())
    };
    
    // Create the request
    let request = CommandRequest {
        command: command.to_string(),
        session_id: session_id.clone(),
        background,
    };
    
    // Send the request
    let response = client
        .post(&server_url)
        .json(&request)
        .send()
        .await?;
    
    // Check for error status
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await?;
        return Err(format!("HTTP Error {}: {}", status, text).into());
    }
    
    // Parse the response
    let result: CommandResponse = response.json().await?;
    
    Ok(result)
}