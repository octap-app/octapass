//! Attachments in an S3-compatible bucket (AWS S3, MinIO, Garage, Backblaze B2,
//! Wasabi, Hetzner, …), signed with AWS Signature Version 4.
//!
//! Only four calls are needed: put, get and delete an object, and a bucket
//! check. Uploads are spooled first, so their length and SHA-256 are known and
//! the payload is signed rather than sent as `UNSIGNED-PAYLOAD`.

use std::fmt;
use std::time::Duration;

use axum::body::Body;
use hmac::{Hmac, Mac};
use reqwest::{Method, StatusCode, Url};
use sha2::{Digest, Sha256};
use tokio_util::io::ReaderStream;

use super::{BoxFuture, Object, ObjectStorage, StorageError, Upload, hex};

/// SHA-256 of an empty body, the payload hash of every request but uploads.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone)]
pub struct S3Config {
    /// `https://s3.eu-central-1.amazonaws.com`, `https://minio.example.com:9000`, …
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// `https://endpoint/bucket/key` instead of `https://bucket.endpoint/key`.
    /// Most self-hosted servers (MinIO, Garage) need it.
    pub path_style: bool,
}

impl fmt::Debug for S3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("path_style", &self.path_style)
            .finish()
    }
}

pub struct S3Storage {
    config: S3Config,
    endpoint: Url,
    http: reqwest::Client,
}

fn remote(error: impl fmt::Display) -> StorageError {
    StorageError::Remote(error.to_string())
}

impl S3Storage {
    pub fn new(config: S3Config) -> Result<Self, StorageError> {
        let endpoint = Url::parse(&config.endpoint).map_err(remote)?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
            return Err(remote("OCTAPASS_S3_ENDPOINT must be an http(s) URL"));
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(60))
            .build()
            .map_err(remote)?;
        Ok(Self {
            config,
            endpoint,
            http,
        })
    }

    /// The URL of an object (or of the bucket, for `None`).
    fn url(&self, key: Option<&str>) -> Url {
        let mut url = self.endpoint.clone();
        let base = url.path().trim_end_matches('/').to_owned();
        let key = key.map(uri_encode).unwrap_or_default();
        if self.config.path_style {
            url.set_path(&format!("{base}/{}/{key}", uri_encode(&self.config.bucket)));
        } else {
            let host = format!(
                "{}.{}",
                self.config.bucket,
                url.host_str().unwrap_or_default()
            );
            url.set_host(Some(&host))
                .expect("a bucket name makes a valid host");
            url.set_path(&format!("{base}/{key}"));
        }
        url
    }

    fn request(&self, method: Method, url: Url, payload_sha256: &str) -> reqwest::RequestBuilder {
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        let now = time::OffsetDateTime::now_utc();
        let amz_date = format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        let authorization = authorization(
            &Credentials {
                access_key_id: &self.config.access_key_id,
                secret_access_key: &self.config.secret_access_key,
                region: &self.config.region,
            },
            &Signed {
                method: method.as_str(),
                host: &host,
                path: url.path(),
                headers: &[],
                payload_sha256,
                amz_date: &amz_date,
            },
        );
        self.http
            .request(method, url)
            .header("x-amz-content-sha256", payload_sha256)
            .header("x-amz-date", amz_date)
            .header("authorization", authorization)
    }
}

impl ObjectStorage for S3Storage {
    fn put<'a>(&'a self, key: &'a str, upload: Upload) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let file = tokio::fs::File::open(upload.path()).await?;
            let body = reqwest::Body::wrap_stream(ReaderStream::with_capacity(file, 64 * 1024));
            let response = self
                .request(Method::PUT, self.url(Some(key)), &upload.sha256)
                .header("content-length", upload.len)
                .header("content-type", "application/octet-stream")
                .body(body)
                .send()
                .await
                .map_err(remote)?;
            check_status("PUT", response.status())
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Object>, StorageError>> {
        Box::pin(async move {
            let response = self
                .request(Method::GET, self.url(Some(key)), EMPTY_SHA256)
                .send()
                .await
                .map_err(remote)?;
            if response.status() == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            check_status("GET", response.status())?;
            let len = response
                .content_length()
                .ok_or_else(|| remote("GET returned no Content-Length"))?;
            Ok(Some(Object {
                len,
                body: Body::from_stream(response.bytes_stream()),
            }))
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let response = self
                .request(Method::DELETE, self.url(Some(key)), EMPTY_SHA256)
                .send()
                .await
                .map_err(remote)?;
            if response.status() == StatusCode::NOT_FOUND {
                return Ok(());
            }
            check_status("DELETE", response.status())
        })
    }

    fn check(&self) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            let response = self
                .request(Method::HEAD, self.url(None), EMPTY_SHA256)
                .send()
                .await
                .map_err(remote)?;
            check_status("HEAD bucket", response.status())
        })
    }
}

fn check_status(call: &str, status: StatusCode) -> Result<(), StorageError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(remote(format!("{call} returned {status}")))
    }
}

/// RFC 3986 percent-encoding of everything but unreserved characters and `/`,
/// as SigV4 canonical URIs for S3 need.
fn uri_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub(crate) struct Credentials<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub region: &'a str,
}

/// What a request signs. `host`, `x-amz-content-sha256` and `x-amz-date` are
/// always signed; `headers` adds more (lower-case names).
pub(crate) struct Signed<'a> {
    pub method: &'a str,
    pub host: &'a str,
    /// Already URI-encoded.
    pub path: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub payload_sha256: &'a str,
    /// `YYYYMMDDTHHMMSSZ`
    pub amz_date: &'a str,
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// The `Authorization` header of AWS Signature Version 4, for requests
/// without a query string.
pub(crate) fn authorization(credentials: &Credentials<'_>, request: &Signed<'_>) -> String {
    let mut headers: Vec<(&str, &str)> = vec![
        ("host", request.host),
        ("x-amz-content-sha256", request.payload_sha256),
        ("x-amz-date", request.amz_date),
    ];
    headers.extend_from_slice(request.headers);
    headers.sort_by_key(|&(name, _)| name);
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let signed_headers = headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{}\n{}\n\n{canonical_headers}\n{signed_headers}\n{}",
        request.method, request.path, request.payload_sha256
    );
    let date = &request.amz_date[..8];
    let scope = format!("{date}/{}/s3/aws4_request", credentials.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        request.amz_date,
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let key = [date, credentials.region, "s3", "aws4_request"]
        .iter()
        .fold(
            format!("AWS4{}", credentials.secret_access_key).into_bytes(),
            |key, part| hmac(&key, part),
        );
    let signature = hex(&hmac(&key, &string_to_sign));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={signed_headers},Signature={signature}",
        credentials.access_key_id
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, Method as HttpMethod, StatusCode as HttpStatus};
    use axum::response::IntoResponse;
    use axum::routing::any;
    use http_body_util::BodyExt;

    use super::*;
    use crate::storage::spool;

    /// The "GET Object" example from the AWS Signature Version 4 documentation.
    #[test]
    fn signs_like_the_aws_example() {
        let credentials = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
        };
        let request = Signed {
            method: "GET",
            host: "examplebucket.s3.amazonaws.com",
            path: "/test.txt",
            headers: &[("range", "bytes=0-9")],
            payload_sha256: EMPTY_SHA256,
            amz_date: "20130524T000000Z",
        };
        assert_eq!(
            authorization(&credentials, &request),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,\
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,\
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    fn config(endpoint: &str, path_style: bool) -> S3Config {
        S3Config {
            endpoint: endpoint.into(),
            bucket: "files".into(),
            region: "eu-central-1".into(),
            access_key_id: "test-key".into(),
            secret_access_key: "test-secret".into(),
            path_style,
        }
    }

    #[test]
    fn builds_path_and_virtual_host_urls() {
        let path = S3Storage::new(config("http://127.0.0.1:9000", true)).unwrap();
        assert_eq!(
            path.url(Some("ab12")).as_str(),
            "http://127.0.0.1:9000/files/ab12"
        );
        assert_eq!(path.url(None).as_str(), "http://127.0.0.1:9000/files/");
        let hosted =
            S3Storage::new(config("https://s3.eu-central-1.amazonaws.com", false)).unwrap();
        assert_eq!(
            hosted.url(Some("ab12")).as_str(),
            "https://files.s3.eu-central-1.amazonaws.com/ab12"
        );
        assert!(S3Storage::new(config("ftp://example.com", true)).is_err());
        assert!(!format!("{:?}", config("http://x", true)).contains("test-secret"));
    }

    /// An in-memory S3 that checks every request's signature and payload hash.
    #[derive(Clone, Default)]
    pub(crate) struct FakeS3 {
        pub objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        /// Answer 503 to everything, as an unreachable provider would.
        pub down: Arc<Mutex<bool>>,
    }

    impl FakeS3 {
        pub async fn start(&self) -> String {
            async fn handle(
                State(fake): State<FakeS3>,
                Path(path): Path<String>,
                method: HttpMethod,
                headers: HeaderMap,
                body: axum::body::Bytes,
            ) -> axum::response::Response {
                if *fake.down.lock().unwrap() {
                    return HttpStatus::SERVICE_UNAVAILABLE.into_response();
                }
                let header = |name: &str| headers[name].to_str().unwrap().to_owned();
                let payload = header("x-amz-content-sha256");
                let expected = authorization(
                    &Credentials {
                        access_key_id: "test-key",
                        secret_access_key: "test-secret",
                        region: "eu-central-1",
                    },
                    &Signed {
                        method: method.as_str(),
                        host: &header("host"),
                        path: &format!("/{path}"),
                        headers: &[],
                        payload_sha256: &payload,
                        amz_date: &header("x-amz-date"),
                    },
                );
                if header("authorization") != expected || hex(&Sha256::digest(&body)) != payload {
                    return HttpStatus::FORBIDDEN.into_response();
                }
                let mut objects = fake.objects.lock().unwrap();
                let Some(key) = path.strip_prefix("files/") else {
                    return HttpStatus::NOT_FOUND.into_response();
                };
                match method {
                    HttpMethod::HEAD if key.is_empty() => HttpStatus::OK.into_response(),
                    HttpMethod::PUT => {
                        objects.insert(key.to_owned(), body.to_vec());
                        HttpStatus::OK.into_response()
                    }
                    HttpMethod::GET => match objects.get(key) {
                        Some(bytes) => bytes.clone().into_response(),
                        None => HttpStatus::NOT_FOUND.into_response(),
                    },
                    HttpMethod::DELETE => {
                        objects.remove(key);
                        HttpStatus::NO_CONTENT.into_response()
                    }
                    _ => HttpStatus::METHOD_NOT_ALLOWED.into_response(),
                }
            }
            let app = Router::new()
                .route("/{*path}", any(handle))
                .with_state(self.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            format!("http://{addr}")
        }
    }

    #[tokio::test]
    async fn talks_to_an_s3_server() {
        let fake = FakeS3::default();
        let storage = S3Storage::new(config(&fake.start().await, true)).unwrap();
        storage.check().await.unwrap();

        let dir = tempfile::tempdir().unwrap();
        let upload = spool(dir.path(), Body::from("ciphertext"), 10)
            .await
            .unwrap();
        storage.put("ab12", upload).await.unwrap();
        assert_eq!(fake.objects.lock().unwrap()["ab12"], b"ciphertext");

        let object = storage.get("ab12").await.unwrap().unwrap();
        assert_eq!(object.len, 10);
        assert_eq!(
            &object.body.collect().await.unwrap().to_bytes()[..],
            b"ciphertext"
        );

        storage.delete("ab12").await.unwrap();
        assert!(storage.get("ab12").await.unwrap().is_none());
        storage.delete("ab12").await.unwrap();

        *fake.down.lock().unwrap() = true;
        assert!(storage.delete("ab12").await.is_err());
        assert!(storage.check().await.is_err());
    }

    #[tokio::test]
    async fn a_wrong_secret_is_refused() {
        let fake = FakeS3::default();
        let mut wrong = config(&fake.start().await, true);
        wrong.secret_access_key = "other".into();
        let storage = S3Storage::new(wrong).unwrap();
        assert!(storage.check().await.is_err());
    }
}
