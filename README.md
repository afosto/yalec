# Yalec - Yet another lets encrypt client

Written in PHP, YALEC aims to be a decoupled LetsEncrypt client.

## Decoupled from a filesystem or webserver

In stead of, for example writing the certificate to the disk under an nginx configuration, this client just returns the 
data that can be used to prepare the validation of the domain.

## Why

Why whould I need this package? At Afosto we run our software in a multi tenant setup, as any other SaaS would do, and
therefore we cannot make use of the many clients that are already out there. 

## Installation

Installing this package is done easily with composer. 
```bash
composer require afosto/yalec
```

## Requirements

- PHP7+
- openssl
- [Flysystem](http://flysystem.thephpleague.com/) (any adapter would do) - to store the Lets Encrypt account information


## Getting started

Getting started is easy. You need to construct a flysystem filesystem, instantiate the client and you can start 
requesting certificates.

### Instantiate the client

To start the client you need 3 things; a username for your LetsEncrypt account, a bootstrapped flysystem and you need to 
decide whether you want to issue `Fake LE Intermediate X1` (staging: `MODE_STAGING`) or `Let's Encrypt Authority X3` (live: `MODE_LIVE`, use for production) certificates.

```php
$filesystem = new Filesystem($adapter);
$client = new Client([
    'username' => 'example@example.org',
    'fs'       => $filesystem,
    'mode'     => Client::MODE_STAGING,
]);
```

While you instantiate the client, when needed a new LetsEcrypt account is created and then agrees to the TOS.


### Prove you own the domain

Before you can obtain a certificate for a given domain you need to prove that you own the given domain(s).

```php
$authorizations = $client->authorize(['example.org', 'www.example.org']);
```

You now have an array of `Authorization` objects. These have the challenges you can use (both `DNS` and `HTTP`) to 
provide proof of ownership.

Use the following loop to get the HTTP validation files:

```php
foreach ($authorizations as $authorization) {
    $file = $authorization->getFile();

    file_put_contents($file->getFilename(), $file->getContents());
    //Or store it in some other persistent storage system like a database

}
```

### Request validation and get the certificate

Once the challenges are in place you can request LetsEncrypt to verify the challenges: 
```php
if ($client->validate($authorizations)) {
    $certificate = $client->getCertificate(['www.123douchestoel.nl', '123douchestoel.nl']);
    
    //Store the certificate and private key where you need it
    file_put_contents('certificate.cert', $certificate->getCertificate());
    file_put_contents('private.key', $certificate->getPrivateKey());
}
```




 
