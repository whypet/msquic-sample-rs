# msquic-sample-rs

## &#x26A0;&#xFE0F; Currently broken

I can't figure out how to fix it, but I'll get to it some day. The server seems to shut down the client's connection for every attempt the client makes to connect.

It's worth noting that the Rust bindings for MsQuic are [experimental](https://github.com/microsoft/msquic/blob/main/docs/BUILD.md#building-for-rust) and undocumented, making them harder to work with.

## Overview

This repository provides a small sample for an MsQuic server & client application written in Rust. The code is similar to the official C sample and the Rust bindings' test module.

## Running

Server example (listens on port 5678 using a certificate hash):
```
./msquic-sample-rs -l -p 5678 -C 7E667EAE73D288D409041081F991FE480DBF004E
```
(where `7E667EAE73D288D409041081F991FE480DBF004E` is my self-signed certificate hash.)

Client example (connects to server running locally at port 5678):
```
./msquic-sample-rs -c 127.0.0.1 -p 5678
```

You will need to use a certificate to get the server running. If you do not already have one, you could create a self-signed one.

### The rest of this README is taken from official MsQuic documentation.

## [Generate Self Signed Certificate](https://github.com/microsoft/msquic/blob/main/docs/Sample.md)
A certificate needs to be available for the server to function. To generate a self-signed certificate, run

### On Windows
```Powershell
New-SelfSignedCertificate -DnsName $env:computername,localhost -FriendlyName MsQuic-Test -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable
```
This works for both Schannel and OpenSSL TLS providers, assuming the KeyExportPolicy parameter is set to Exportable. The Thumbprint received from the command is then passed to the sample server at startup. Copy the thumbprint received.

### On Linux
```Powershell
openssl req  -nodes -new -x509  -keyout server.key -out server.cert
```
This works with OpenSSL TLS Provider. It can also be used for Windows OpenSSL, however we recommend the certificate store method above for ease of use. Currently key files with password protections are not supported. With these files, they can be passed to the sample server with `-cert_file:path/to/server.cert` and `-key_file path/to/server.key` parameters.