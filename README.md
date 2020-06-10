# Relaynet JVM Library

JVM library for the core of Relaynet. [Read documentation online](https://docs.relaycorp.tech/relaynet-jvm/).

## Development

This project uses [Gradle](https://gradle.org/), so the only system dependency is a Java JDK. To install the project along with its dependencies, run `./gradlew build` (or `gradlew.bat build` on Windows).

Additional Gradle tasks include:

- `test`: Runs the unit test suite.
- `dokka`: Generates the API documentation.
- `publish`: Publishes the library to the local Maven repository on `build/repository`.
