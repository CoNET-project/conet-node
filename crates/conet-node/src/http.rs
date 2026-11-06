//! Minimal HTTP/1.1 for the node wire: read one request with hard limits, write the same
//! response shapes as CoNET-SI (`htmlResponse.ts`). Forwarding works on the raw socket, so a
//! full HTTP stack is not needed and would get in the way of SSE passthrough.
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_body_bytes: usize,
    pub header_timeout: Duration,
    pub body_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_headers: 64,
            max_body_bytes: 256 * 1024,
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Header lines as `Name: value`, in arrival order (hop sigs are parsed from these).
    pub header_lines: Vec<String>,
    pub body: Vec<u8>,
    /// Bytes that arrived after the body (pipelined data); forwarded upstream untouched.
    pub leftover: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum ReadError {
    Closed,
    Timeout,
    TooLarge,
    Malformed,
    Io,
}

pub async fn read_request<S: AsyncRead + Unpin>(
    s: &mut S,
    lim: &Limits,
) -> Result<Request, ReadError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let head_end = timeout(lim.header_timeout, async {
        loop {
            if let Some(i) = find(&buf, b"\r\n\r\n") {
                return Ok(i + 4);
            }
            if buf.len() > lim.max_header_bytes {
                return Err(ReadError::TooLarge);
            }
            let n = s.read(&mut chunk).await.map_err(|_| ReadError::Io)?;
            if n == 0 {
                return Err(ReadError::Closed);
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .map_err(|_| ReadError::Timeout)??;
    if head_end > lim.max_header_bytes {
        return Err(ReadError::TooLarge);
    }

    let mut headers = vec![httparse::EMPTY_HEADER; lim.max_headers];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(&buf[..head_end]) {
        Ok(httparse::Status::Complete(_)) => {}
        Err(httparse::Error::TooManyHeaders) => return Err(ReadError::TooLarge),
        _ => return Err(ReadError::Malformed),
    }
    let method = req.method.ok_or(ReadError::Malformed)?.to_string();
    let path = req.path.ok_or(ReadError::Malformed)?.to_string();
    let mut header_lines = Vec::with_capacity(req.headers.len());
    let mut content_length: usize = 0;
    for h in req.headers.iter() {
        let v = std::str::from_utf8(h.value).map_err(|_| ReadError::Malformed)?;
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            // SI only speaks Content-Length; refuse chunked bodies rather than guess.
            return Err(ReadError::Malformed);
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            content_length = v.trim().parse().map_err(|_| ReadError::Malformed)?;
        }
        header_lines.push(format!("{}: {}", h.name, v));
    }
    if content_length > lim.max_body_bytes {
        return Err(ReadError::TooLarge);
    }
    let mut rest = buf.split_off(head_end);
    timeout(lim.body_timeout, async {
        while rest.len() < content_length {
            let n = s.read(&mut chunk).await.map_err(|_| ReadError::Io)?;
            if n == 0 {
                return Err(ReadError::Closed);
            }
            rest.extend_from_slice(&chunk[..n]);
        }
        Ok(())
    })
    .await
    .map_err(|_| ReadError::Timeout)??;
    let leftover = rest.split_off(content_length);
    Ok(Request {
        method,
        path,
        header_lines,
        body: rest,
        leftover,
    })
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

const CORS: &str = "Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n\
Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Accept, Origin\r\n\
Access-Control-Max-Age: 86400\r\n";

fn date() -> String {
    httpdate::fmt_http_date(std::time::SystemTime::now())
}

/// SI `response200Html`.
pub fn ok_200(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nDate: {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: keep-alive\r\n{CORS}Access-Control-Allow-Credentials: true\r\nAccess-Control-Expose-Headers: Content-Length, Content-Type\r\n\r\n{body}",
        date(),
        body.len()
    )
    .into_bytes()
}

/// SI `distorySocket`: an nginx-looking 404 page.
pub fn not_found() -> Vec<u8> {
    let header = "404 Not Found";
    let html = format!("<html>\r\n<head><title>{header}</title></head>\r\n<body>\r\n<center><h1>{header}</h1></center>\r\n<hr><center>nginx/1.18.0</center>\r\n</body>\r\n</html>\r\n");
    format!(
        "HTTP/1.1 {header}\r\nServer: nginx/1.18.0\r\nDate: {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: keep-alive\r\n{CORS}\r\n{html}",
        date(),
        html.len()
    )
    .into_bytes()
}

/// CORS preflight for `/post` (browsers send OPTIONS before POST).
pub fn options_204() -> Vec<u8> {
    format!("HTTP/1.1 204 No Content\r\nServer: nginx/1.18.0\r\nDate: {}\r\n{CORS}Content-Length: 0\r\nConnection: keep-alive\r\n\r\n", date()).into_bytes()
}

/// SI `otherRequestForNet`: the SI-to-SI forward request.
pub fn forward_request(host: &str, port: u16, hop_header_line: &str, body: &str) -> Vec<u8> {
    let host = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let extra = if hop_header_line.is_empty() {
        String::new()
    } else {
        format!("{hop_header_line}\r\n")
    };
    format!(
        "POST /post HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n{extra}Content-Type: application/json;charset=UTF-8\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_body_and_leftover() {
        let raw = b"POST /post HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nX-CoNET-Hop-Sigs: abc\r\n\r\nbodyEXTRA".to_vec();
        let mut r = &raw[..];
        let req = read_request(&mut r, &Limits::default()).await.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, b"body");
        assert_eq!(req.leftover, b"EXTRA");
        assert!(req
            .header_lines
            .iter()
            .any(|l| l == "X-CoNET-Hop-Sigs: abc"));
    }

    #[tokio::test]
    async fn refuses_large_and_chunked() {
        let lim = Limits {
            max_body_bytes: 10,
            ..Default::default()
        };
        let raw = b"POST /post HTTP/1.1\r\nContent-Length: 11\r\n\r\n".to_vec();
        assert_eq!(
            read_request(&mut &raw[..], &lim).await.unwrap_err(),
            ReadError::TooLarge
        );
        let raw = b"POST /post HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        assert_eq!(
            read_request(&mut &raw[..], &lim).await.unwrap_err(),
            ReadError::Malformed
        );
        let big = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(20_000));
        assert_eq!(
            read_request(&mut big.as_bytes(), &Limits::default())
                .await
                .unwrap_err(),
            ReadError::TooLarge
        );
    }
}
