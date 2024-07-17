use std::ffi::{c_char, CStr};

use anyhow::Context;
use lettre::{
    message::{header::Header, Mailboxes, MessageBuilder},
    transport::smtp::{
        authentication::{Credentials, Mechanism},
        client::{CertificateStore, TlsParameters},
    },
    SmtpTransport, Transport,
};

static SUCCESS: i32 = 0;
static FAILURE: i32 = -1;

static ERR_HOST_NOT_PROVIDED: &CStr = unsafe {
    CStr::from_bytes_with_nul_unchecked(
        b"SMTP host address not provided; specify using the 'SMTP' INI config\0",
    )
};

static ERR_FROM_NOT_PROVIDED: &CStr = unsafe {
    CStr::from_bytes_with_nul_unchecked(
        b"Mail from address not provided; specify using the 'sendmail_from' INI config\0",
    )
};

static ERR_ONLY_USERNAME_OR_PASSWORD_PROVIDED: &CStr = unsafe {
    CStr::from_bytes_with_nul_unchecked(
        b"Only username or password provided. You must provide neither to disable authentication, or both \
        to enable authentication. Specify using the 'sendmail_username' and 'sendmail_password' INI configs\0",
    )
};

static ERR_GENERIC_ERROR: &CStr = unsafe {
    CStr::from_bytes_with_nul_unchecked(
        b"Failed to send message. Check server logs for more details.\0",
    )
};

#[derive(thiserror::Error, Debug)]
enum SendMailError {
    #[error("Host not provided")]
    HostNotProvided,
    #[error("From address not provided")]
    FromNotProvided,
    #[error("Username and password must be provided together")]
    OnlyUsernameOrPasswordProvided,
    #[error("{0}")]
    NetworkError(#[from] anyhow::Error),
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn wasix_sendmail(
    host: *const c_char,
    port: u16,
    username: *const c_char,
    password: *const c_char,
    error_message: *mut *const c_char,
    headers: *const c_char,
    subject: *const c_char,
    mail_from: *const c_char,
    mail_to: *const c_char,
    data: *const c_char,
) -> i32 {
    match send_mail(
        host, port, username, password, headers, subject, mail_from, mail_to, data,
    ) {
        Ok(()) => SUCCESS,
        Err(e) => unsafe {
            let error_description = match e {
                SendMailError::HostNotProvided => ERR_HOST_NOT_PROVIDED,
                SendMailError::FromNotProvided => ERR_FROM_NOT_PROVIDED,
                SendMailError::OnlyUsernameOrPasswordProvided => {
                    ERR_ONLY_USERNAME_OR_PASSWORD_PROVIDED
                }
                SendMailError::NetworkError(e) => {
                    let err_desc = format!("{e:?}");
                    eprintln!("wasix_sendmail error: {err_desc}");
                    // Leave out the initial A to make it work with both capital and small A
                    if err_desc.contains("uthentication") {
                        eprintln!(
                            "Hint: you can use the (non-standard) sendmail_username and sendmail_password INI configs to provide \
                            authentication information"
                        );
                    }
                    ERR_GENERIC_ERROR
                }
            };

            if !error_message.is_null() {
                *error_message = error_description.as_ptr() as *const _;
            }

            FAILURE
        },
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref, clippy::too_many_arguments)]
fn send_mail(
    host: *const c_char,
    port: u16,
    username: *const c_char,
    password: *const c_char,
    headers: *const c_char,
    subject: *const c_char,
    mail_from: *const c_char,
    mail_to: *const c_char,
    data: *const c_char,
) -> Result<(), SendMailError> {
    unsafe {
        let mut message_builder = lettre::Message::builder();

        // To
        let mail_to = if mail_to.is_null() {
            return Ok(());
        } else {
            CStr::from_ptr(mail_to as *const _)
                .to_str()
                .context("mail_to contains invalid UTF-8 characters")?
        };

        if mail_to.is_empty() {
            return Ok(());
        }

        for addr in mail_to
            .parse::<Mailboxes>()
            .context("Failed to parse mail_to address")?
        {
            message_builder = message_builder.to(addr);
        }

        // From
        if mail_from.is_null() {
            return Err(SendMailError::FromNotProvided);
        }
        let mail_from = CStr::from_ptr(mail_from as *const _)
            .to_str()
            .context("mail_from contains invalid UTF-8 characters")?;

        for addr in mail_from
            .parse::<Mailboxes>()
            .context("Failed to parse mail_from address")?
        {
            message_builder = message_builder.from(addr);
        }

        // Subject
        let subject = if subject.is_null() {
            ""
        } else {
            CStr::from_ptr(subject as *const _)
                .to_str()
                .context("Subject contains invalid UTF-8 characters")?
        };
        message_builder = message_builder.subject(subject);

        // Additional headers
        let headers = if headers.is_null() {
            vec![]
        } else {
            CStr::from_ptr(headers as *const _)
                .to_str()
                .context("headers contains invalid UTF-8 characters")?
                .split('\n')
                .filter_map(|h| {
                    let trimmed = h.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed)
                    }
                })
                .collect::<Vec<_>>()
        };
        for header in headers {
            message_builder = parse_and_append_header(message_builder, header)?;
        }

        // Message body
        let data = if data.is_null() {
            ""
        } else {
            CStr::from_ptr(data as *const _)
                .to_str()
                .context("Data contains invalid UTF-8 characters")?
        };

        let message = message_builder
            .body(data.to_owned())
            .context("Failed to build message")?;

        // Host
        if host.is_null() {
            return Err(SendMailError::HostNotProvided);
        }
        let host = CStr::from_ptr(host as *const _)
            .to_str()
            .context("Host string contains invalid UTF-8 characters")?;

        // TLS params
        let tls = TlsParameters::builder("sandbox.smtp.mailtrap.io".to_owned())
            .certificate_store(CertificateStore::Default)
            .build_rustls()
            .context("Failed to build certificate store")?;

        // Transport builder
        let mut transport_builder = SmtpTransport::relay(host)
            .context("Invalid host name")?
            .port(port)
            .tls(lettre::transport::smtp::client::Tls::Opportunistic(tls));

        // Authentication
        let username = if username.is_null() {
            None
        } else {
            let username = CStr::from_ptr(username as *const _)
                .to_str()
                .context("Username contains invalid UTF-8 characters")?;
            if username.is_empty() {
                None
            } else {
                Some(username)
            }
        };

        let password = if password.is_null() {
            None
        } else {
            let password = CStr::from_ptr(password as *const _)
                .to_str()
                .context("Password contains invalid UTF-8 characters")?;
            if password.is_empty() {
                None
            } else {
                Some(password)
            }
        };

        transport_builder = match (username, password) {
            (None, None) => transport_builder,
            (Some(username), Some(password)) => transport_builder
                .authentication(vec![Mechanism::Login])
                .credentials(Credentials::new(username.to_owned(), password.to_owned())),
            _ => return Err(SendMailError::OnlyUsernameOrPasswordProvided),
        };

        // Send the message
        let mailer = transport_builder.build();

        mailer.send(&message).context("Failed to send mail")?;

        Ok(())
    }
}

macro_rules! maybe_parse_header {
    ($header_ty:ident, $builder:ident, $header:ident) => {
        if let Ok(header) = lettre::message::header::$header_ty::parse($header) {
            return Ok($builder.header(header));
        }
    };
}

// Is there really no better way to do this?
fn parse_and_append_header(
    builder: MessageBuilder,
    header: &str,
) -> anyhow::Result<MessageBuilder> {
    maybe_parse_header!(Bcc, builder, header);
    maybe_parse_header!(Cc, builder, header);
    maybe_parse_header!(Comments, builder, header);
    maybe_parse_header!(ContentDisposition, builder, header);
    maybe_parse_header!(ContentId, builder, header);
    maybe_parse_header!(ContentLocation, builder, header);
    maybe_parse_header!(ContentType, builder, header);
    maybe_parse_header!(Date, builder, header);
    maybe_parse_header!(From, builder, header);
    maybe_parse_header!(InReplyTo, builder, header);
    maybe_parse_header!(MessageId, builder, header);
    maybe_parse_header!(MimeVersion, builder, header);
    maybe_parse_header!(References, builder, header);
    maybe_parse_header!(ReplyTo, builder, header);
    maybe_parse_header!(Sender, builder, header);
    maybe_parse_header!(Subject, builder, header);
    maybe_parse_header!(To, builder, header);
    maybe_parse_header!(UserAgent, builder, header);
    anyhow::bail!("Failed to parse header line");
}
