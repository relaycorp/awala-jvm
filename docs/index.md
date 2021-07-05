---
layout: page
title: Awala JVM
---
# Awala JVM Library

This library implements the core of [Awala](https://awala.network/) (fka _Relaynet_) and is meant to be used in any software using the network on the JVM -- including Android and server-side apps.

Please note that this documentation is mostly incomplete because the interface exposed by this library is changing rapidly as of this writing. Also note that the examples in this documentation won't work until a gateway (e.g., [the Android Gateway](https://github.com/relaycorp/relaynet-gateway-android)) has been implemented.

## Install

This library runs on Java 8+ and is available on [Maven Central](https://search.maven.org/artifact/tech.relaycorp/awala). To install it via Gradle, use:

```
implementation 'tech.relaycorp:awala:1.+'
```

## Use

This library can be used for different purposes, so please refer to the documentation for your specific use case:

Most people will be interested in [adding Awala support to their app](howto-service.md), whether the app is pre-existing or is being built from scratch.

Relaycorp provides implementations for gateways and couriers, so if you're contributing to those implementations or for whatever reason you'd like to build your own, please refer to the follow documents:

- [Implementing a gateway](howto-gateway.md).
- [Implementing a courier](./howto-courier.md).

[Read API documentation](./api/awala/).

## Specs supported

This library supports the following Awala specs:

- [RS-000 (Awala Core)](https://specs.awala.network/RS-000).
- [RS-001 (RAMF v1)](https://specs.awala.network/RS-001).
- [RS-002 (Awala PKI)](https://specs.awala.network/RS-002).
- [RS-003 (Awala Channel Session Protocol)](https://specs.awala.network/RS-003).
- [RS-018 (Awala Cryptographic Algorithms, Version 1)](https://specs.awala.network/RS-018). In addition to the required algorithms, the following are supported:
  - Hashing functions: SHA-384 and SHA-512.
  - Ciphers: AES-192 and AES-256.

## Support

If you have any questions or comments, [create an issue on the GitHub project](https://github.com/relaycorp/awala-jvm/issues/new/choose).

## Updates

Releases are automatically published on GitHub and JCenter, and the [changelog can be found on GitHub](https://github.com/relaycorp/awala-jvm/releases). This project uses [semantic versioning](https://semver.org/).
