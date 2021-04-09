---
title: Implementing a courier
nav_order: 7
permalink: /couriers
---
# Implementing a courier

If you're implementing a courier, you'll only need a very small subset of this library.

## Processing RAMF messages

You'll need the [`Cargo`](/awala-jvm/api/relaynet/tech.relaycorp.relaynet.messages/-cargo/) and [`CargoCollectionAuthorization`](/awala-jvm/api/relaynet/tech.relaycorp.relaynet.messages/-cargo-collection-authorization/) (CCA) classes to deserialize and inspect their corresponding RAMF messages.

It is important to call the `validate()` method on any RAMF message received from any external source. Deserializing RAMF messages only proves that they are syntactically valid, but they may still be invalid (e.g., the message might've been created after the sender's certificate expired).

## Delivering cargo

When delivering cargo to a public gateway via a cargo relay implementation (e.g., CogRPC), you'll need to pass [`CargoRelayRequest`](/awala-jvm/api/relaynet/tech.relaycorp.relaynet/-cargo-delivery-request/) instances to it so that you can track and delete cargo as it's safely delivered to the gateway.

The actual way to pass such instances will depend entirely on the cargo relay library, so make sure it read its documentation.

## Example

To see this library in action in a courier implementation, [check out how the Relaynet Courier by Relaycorp](https://github.com/relaycorp/relaynet-courier-android/search?q=%22tech.relaycorp.relaynet%22).
