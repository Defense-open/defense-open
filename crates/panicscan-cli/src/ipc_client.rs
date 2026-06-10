//! IPC istemcisi — `panicscan-cli`'dan daemon'a bağlanır.
//!
//! Platform:
//!   Windows → Named Pipe
//!   Unix    → Unix Socket

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use panicscan_daemon::ipc_types::{IpcRequest, IpcResponse};

/// Daemon'a bir istek gönderir ve cevabı döndürür.
pub async fn send_request(request: &IpcRequest) -> Result<IpcResponse> {
    let socket_path = panicscan_daemon::ipc::socket_path();
    let json = serde_json::to_string(request)? + "\n";

    #[cfg(unix)]
    {
        use tokio::net::UnixStream;

        let stream = UnixStream::connect(&socket_path).await.with_context(|| {
            format!(
                "Daemon'a bağlanılamadı: {socket_path}\n\
                 Daemon çalışıyor mu? → sudo panicscan-daemon start"
            )
        })?;

        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        write_half.write_all(json.as_bytes()).await?;
        write_half.flush().await?;

        let mut line = String::new();
        reader.read_line(&mut line).await?;

        serde_json::from_str(line.trim()).with_context(|| format!("Geçersiz daemon cevabı: {line}"))
    }

    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;

        let pipe = ClientOptions::new().open(&socket_path).with_context(|| {
            format!(
                "Daemon'a bağlanılamadı: {socket_path}\n\
                 Daemon çalışıyor mu? → panicscan-daemon start"
            )
        })?;

        let (read_half, mut write_half) = tokio::io::split(pipe);
        let mut reader = BufReader::new(read_half);

        write_half.write_all(json.as_bytes()).await?;
        write_half.flush().await?;

        let mut line = String::new();
        reader.read_line(&mut line).await?;

        serde_json::from_str(line.trim()).with_context(|| format!("Geçersiz daemon cevabı: {line}"))
    }
}
