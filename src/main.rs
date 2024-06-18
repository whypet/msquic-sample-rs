use std::{env, ffi::{c_void, CString}, io::{self, Read}, mem, num::ParseIntError, path::Path};

use clap::{arg, builder::ValueParser, command, value_parser, ArgGroup, ArgMatches, Command};
use color_eyre::eyre::{self, eyre};
use msquic::{Addr, Api, Buffer, CertificateFile, CertificateFileProtected, CertificateHash, Configuration, Connection, ConnectionEvent, CredentialConfig, Handle, Listener, ListenerEvent, Registration, RegistrationConfig, Settings, StreamEvent};

const APP_NAME: &'static str = "msquic-sample-rs";

#[allow(dead_code)]
struct CredentialHelper {
    pub config: CredentialConfig,

    pub hash: CertificateHash,
    pub file: CertificateFile,
    pub file_protected: CertificateFileProtected,

    pub private_key_file: Option<CString>,
    pub certificate_file: Option<CString>,
    pub private_key_password: Option<CString>
}

struct Server {
    pub api: Api,
    pub alpn: Buffer,
    pub addr: Addr,
    pub reg: Option<Registration>,
    pub config: Option<Configuration>,
    pub listener: Option<Listener>
}

struct Client {
    pub api: Api,
    pub alpn: Buffer,
    pub server_name: Option<String>,
    pub port: u16,
    pub reg: Option<Registration>,
    pub config: Option<Configuration>,
    pub connection: Option<Connection>
}

impl CredentialHelper {
    fn new() -> CredentialHelper {
        unsafe { mem::zeroed() }
    }

    fn init_from_file(&mut self, cert_file: &str, key_file: &str, password: Option<&str>) {
        if let Some(pw) = password {
            self.config.cred_type = msquic::CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;

            self.file_protected.private_key_file = self.private_key_file.insert(CString::new(key_file).unwrap()).as_ptr();
            self.file_protected.certificate_file = self.certificate_file.insert(CString::new(cert_file).unwrap()).as_ptr();
            self.file_protected.private_key_password = self.private_key_password.insert(CString::new(pw).unwrap()).as_ptr();

            self.config.certificate.file_protected = &self.file_protected;
        } else {
            self.config.cred_type = msquic::CREDENTIAL_TYPE_CERTIFICATE_FILE;

            self.private_key_file = Some(CString::new(key_file).unwrap());
            self.certificate_file = Some(CString::new(cert_file).unwrap());

            self.file.private_key_file = self.private_key_file.insert(CString::new(key_file).unwrap()).as_ptr();
            self.file.certificate_file = self.certificate_file.insert(CString::new(cert_file).unwrap()).as_ptr();

            self.config.certificate.file = &self.file;
        }
    }

    fn init_from_hash(&mut self, cert_hash: &str) {
        self.config.cred_type = msquic::CREDENTIAL_TYPE_CERTIFICATE_HASH;

        self.hash.sha_hash = hash_decode(cert_hash).unwrap();

        self.config.certificate.hash = &self.hash;
    }
}

impl Server {
    pub fn new() -> Server {
        Server {
            api: Api::new(),
            alpn: Buffer::from("sample"),
            addr: Addr::ipv4(msquic::ADDRESS_FAMILY_UNSPEC, 0, 0),
            reg: None,
            config: None,
            listener: None
        }
    }

    pub fn init(&mut self, cli_matches: &ArgMatches) {
        self.addr = Addr::ipv4(
            msquic::ADDRESS_FAMILY_UNSPEC,
            cli_matches.get_one::<u16>("port").unwrap().to_be(),
            0
        );

        let reg_config = RegistrationConfig {
            app_name: APP_NAME.as_ptr() as *const i8,
            execution_profile: msquic::EXECUTION_PROFILE_LOW_LATENCY
        };

        self.reg = Some(Registration::new(&self.api, &reg_config));

        self.config = Some(Configuration::new(
            self.reg.as_ref().unwrap(),
            &self.alpn,
            Settings::new()
                .set_idle_timeout_ms(30000)
                .set_peer_bidi_stream_count(1)
        ));

        let mut cred_helper = CredentialHelper::new();
        open_credential_config(&mut cred_helper, &cli_matches);

        self.config.as_ref().unwrap().load_credential(&cred_helper.config);

        self.listener = Some(Listener::new(
            self.reg.as_ref().unwrap(),
            Server::on_listener,
            self as *const Server as *const c_void
        ));
    }

    pub fn start(&self) {
        self.listener.as_ref().unwrap().start(&self.alpn, 1, &self.addr);
    }

    extern "C" fn on_stream(
        stream: Handle,
        context: *mut c_void,
        event: &StreamEvent
    ) -> u32 {
        let connection = unsafe { &*(context as *const Connection) };
    
        match event.event_type {
            msquic::STREAM_EVENT_SEND_COMPLETE => println!("[Strm][{:p}] Data sent", stream),
            msquic::STREAM_EVENT_RECEIVE => println!("[Strm][{:p}] Data received", stream),
            msquic::STREAM_EVENT_PEER_SEND_SHUTDOWN => println!("[Strm][{:p}] Peer shut down", stream),
            msquic::STREAM_EVENT_PEER_SEND_ABORTED => println!("[Strm][{:p}] Peer aborted", stream),
            msquic::STREAM_EVENT_SHUTDOWN_COMPLETE => {
                println!("[Strm][{:p}] Stream shut down complete", stream);
                connection.stream_close(stream);
            },
            _ => {}
        }
    
        0
    }

    extern "C" fn on_connection(
        _connection: Handle,
        context: *mut c_void,
        event: &ConnectionEvent
    ) -> u32 {
        let connection = unsafe { &*(context as *const Connection) };
    
        match event.event_type {
            msquic::CONNECTION_EVENT_CONNECTED => println!("[conn][{:p}] Connected", connection),
            msquic::CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT =>
                println!("[conn][{:p}] ({:#x}) Shut down by transport", connection, unsafe { event.payload.shutdown_initiated_by_transport.status }),
            msquic::CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER =>
                println!("[conn][{:p}] ({}) Shut down by peer", connection, unsafe { event.payload.shutdown_initiated_by_peer.error_code }),
            msquic::CONNECTION_EVENT_SHUTDOWN_COMPLETE => println!("[conn][{:p}] Shut down complete", connection),
            msquic::CONNECTION_EVENT_PEER_STREAM_STARTED => {
                let stream = unsafe { event.payload.peer_stream_started.stream };
    
                println!("[strm][{:p}] Peer started", unsafe { event.payload.peer_stream_started.stream });
    
                connection.set_stream_callback_handler(
                    stream,
                    Server::on_stream,
                    context
                );
            },
            msquic::CONNECTION_EVENT_RESUMED => println!("[conn][{:p}] Connection resumed", connection),
            _ => {}
        }
    
        0
    }
    
    extern "C" fn on_listener(
        _listener: Handle,
        _context: *mut c_void,
        event: &ListenerEvent
    ) -> u32 {
        let context = unsafe { &*(_context as *const Server) };
    
        match event.event_type {
            msquic::LISTENER_EVENT_NEW_CONNECTION => unsafe {
                let connection = Connection::from_parts(event.payload.new_connection.connection, &context.api);
                connection.set_configuration(context.config.as_ref().unwrap());
                connection.set_callback_handler(
                    Server::on_connection,
                    &connection as *const Connection as *const c_void
                );
    
                0
            },
            _ => 0x80004002 // QUIC_STATUS_NOT_SUPPORTED
        }
    }    
}

impl Client {
    pub fn new() -> Client {
        Client {
            api: Api::new(),
            alpn: Buffer::from("sample"),
            server_name: None,
            port: 0,
            reg: None,
            config: None,
            connection: None
        }
    }

    pub fn init(&mut self, cli_matches: &ArgMatches) {
        self.server_name = Some(cli_matches.get_one::<String>("connect").unwrap().clone());
        self.port = *cli_matches.get_one::<u16>("port").unwrap();
    
        let reg_config = RegistrationConfig {
            app_name: APP_NAME.as_ptr() as *const i8,
            execution_profile: msquic::EXECUTION_PROFILE_LOW_LATENCY
        };
        
        self.reg = Some(Registration::new(&self.api, &reg_config));
    
        self.config = Some(Configuration::new(
            self.reg.as_ref().unwrap(),
            &self.alpn,
            Settings::new()
                .set_idle_timeout_ms(30000)
        ));
        
    
        let mut cred_config = CredentialConfig::new_client();
        cred_config.cred_flags |= msquic::CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    
        self.config.as_ref().unwrap().load_credential(&cred_config);

        self.connection = Some(Connection::new(self.reg.as_ref().unwrap()));

        self.connection.as_ref().unwrap().open(
            self.reg.as_ref().unwrap(),
            Client::on_connection,
            self.connection.as_ref().unwrap() as *const Connection as *const c_void
        );
    }

    pub fn start(&self) {
        let config = self.config.as_ref().unwrap();
        let connection = self.connection.as_ref().unwrap();
        
        connection.start(
            config,
            self.server_name.as_ref().unwrap(),
            self.port
        );
    }

    extern "C" fn on_connection(
        _connection: Handle,
        context: *mut c_void,
        event: &ConnectionEvent
    ) -> u32 {
        let connection = unsafe { &*(context as *const Connection) };
    
        match event.event_type {
            msquic::CONNECTION_EVENT_CONNECTED => println!("[conn][{:p}] Connected", connection),
            msquic::CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT =>
                println!("[conn][{:p}] ({:#x}) Shut down by transport", connection, unsafe { event.payload.shutdown_initiated_by_transport.status }),
            msquic::CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER =>
                println!("[conn][{:p}] ({}) Shut down by peer", connection, unsafe { event.payload.shutdown_initiated_by_peer.error_code }),
            msquic::CONNECTION_EVENT_SHUTDOWN_COMPLETE => println!("[conn][{:p}] Shut down complete", connection),
            msquic::CONNECTION_EVENT_RESUMED => println!("[conn][{:p}] Connection resumed", connection),
            _ => {}
        }
    
        0
    }
}

fn hash_decode(input: &str) -> Option<[u8; 20]> {
    let vec_wrapped = (0..input.len() / 2)
        .map(|i| u8::from_str_radix(&input[i * 2..(i + 1) * 2], 16))
        .collect::<Result<Vec<u8>, ParseIntError>>();

    if let Ok(vec) = vec_wrapped {
        if let Ok(buf) = vec.try_into() {
            return Some(buf);
        }
    }
    
    None
}

fn unwrap_quoted_str(s: &str) -> &str {
    let mut chars = s.chars();
    if chars.next() == Some('"') && chars.last() == Some('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn open_credential_config(cred_helper: &mut CredentialHelper, cli_matches: &ArgMatches) {
    let cert = cli_matches.get_one::<String>("certificate").unwrap();
    let key_file = cli_matches.get_one::<String>("key_file");
    let password = cli_matches.get_one::<String>("password");

    if Path::new(cert).exists() {
        if let Some(pw) = password {
            CredentialHelper::init_from_file(cred_helper, cert, key_file.unwrap(), Some(&pw))
        } else {
            CredentialHelper::init_from_file(cred_helper, cert, key_file.unwrap(), None)
        }
    } else {
        CredentialHelper::init_from_hash(cred_helper, cert);
    }
}

fn cli() -> Command {
    let parse_certificate = |s: &str| {
        let cert = unwrap_quoted_str(s);

        if Path::new(cert).exists() || (cert.len() == 40 && cert.chars().all(|c| c.is_ascii_hexdigit())) {
            Result::<String, String>::Ok(String::from(cert))
        } else {
            Result::<String, String>::Err(String::from("invalid certificate file or hash"))
        }
    };

    let parse_keyfile = |s: &str| {
        let keyfile = unwrap_quoted_str(s);

        if Path::new(keyfile).exists() {
            Result::<String, String>::Ok(String::from(keyfile))
        } else {
            Result::<String, String>::Err(String::from("invalid key file"))
        }
    };

    command!()
        .args([
            arg!(connect: -c --connect <SERVER_NAME> "Connects to a server"),
            arg!(listen: -l --listen "Listens for incoming connections"),
            arg!(port: -p --port <PORT> "Server port")
                .required(true)
                .value_parser(value_parser!(u16)),
            arg!(certificate: -C --certificate <CERT> "Certificate hash or file")
                .required(true)
                .value_parser(ValueParser::new(parse_certificate)),
            arg!(key_file: -k --keyfile <FILE> "Key file (unused when certificate hash is provided)")
                .value_parser(ValueParser::new(parse_keyfile)),
            arg!(password: -P --password <PASSWORD> "Password for certificate file if protected")
                .value_parser(value_parser!(String))
        ])
        .group(ArgGroup::new("functions")
            .args([ "connect", "listen" ])
            .required(true))
        .group(ArgGroup::new("server")
            .args([ "certificate", "key_file", "password" ])
            .multiple(true)
            .conflicts_with("connect"))
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    let cli_matches = cli().get_matches();

    if let Some(cert) = cli_matches.get_one::<String>("certificate") {
        if Path::new(cert).exists() && !cli_matches.contains_id("key_file") {
            return Err(eyre!("certificate file passed without key file"));
        }
    }

    if cli_matches.get_flag("listen") {
        println!("[QUIC server]");

        let mut server = Server::new();
        server.init(&cli_matches);
        server.start();
        
        io::stdin().bytes().next();

        Ok(())
    } else if cli_matches.contains_id("connect") {
        println!("[QUIC client]");

        let mut client = Client::new();
        client.init(&cli_matches);
        client.start();

        io::stdin().bytes().next();

        Ok(())
    } else {
        println!("did not request to listen nor to connect, doing nothing");

        Ok(())
    }
}

#[test]
fn test_hash() {
    let buf = hash_decode("000102030405060708090A0B0C0D0E0F10111213").unwrap();
    println!("{:?}", buf);
}