/*
 * This file was generated by the Gradle 'init' task.
 *
 * This generated file contains a sample Kotlin library project to get you started.
 */
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

group = "tech.relaycorp"

plugins {
    // Apply the Kotlin JVM plugin to add support for Kotlin.
    id("org.jetbrains.kotlin.jvm") version "1.9.23"

    // Apply the java-library plugin for API and implementation separation.
    `java-library`

    id("org.jetbrains.dokka") version "1.9.20"

    id("org.jlleitschuh.gradle.ktlint") version "12.1.1"

    jacoco

    signing
    `maven-publish`
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
}

repositories {
    mavenCentral()
}

dependencies {
    val kotlinCoroutinesVersion = "1.8.0"
    val bouncyCastleVersion = "1.70"
    val junitJuniperVersion = "5.10.2"

    // Align versions of all Kotlin components
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$kotlinCoroutinesVersion")

    // Bouncy Castle
    implementation("org.bouncycastle:bcpkix-jdk15on:$bouncyCastleVersion")
    implementation("org.bouncycastle:bcprov-jdk15on:$bouncyCastleVersion") // ASN.1 serialization

    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("org.junit.jupiter:junit-jupiter:$junitJuniperVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-params:$junitJuniperVersion")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:$kotlinCoroutinesVersion")
}

java {
    withJavadocJar()
    withSourcesJar()
}

jacoco {
    toolVersion = "0.8.8"
}

tasks.jacocoTestReport {
    reports {
        xml.required.set(true)
        html.required.set(true)
        html.outputLocation.set(file("$buildDir/reports/coverage"))
    }
}

tasks.jacocoTestCoverageVerification {
    violationRules {
        rule {
            limit {
                counter = "CLASS"
                value = "MISSEDCOUNT"
                maximum = "0".toBigDecimal()
            }
            limit {
                counter = "METHOD"
                value = "MISSEDCOUNT"
                maximum = "0".toBigDecimal()
            }

            limit {
                counter = "BRANCH"
                value = "MISSEDCOUNT"
                maximum = "2".toBigDecimal()
            }
        }
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
    finalizedBy("jacocoTestReport")
    doLast {
        println("View code coverage at:")
        println("file://$buildDir/reports/coverage/index.html")
    }
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
        allWarningsAsErrors = true
        freeCompilerArgs = freeCompilerArgs +
            arrayOf(
                "-opt-in=kotlin.RequiresOptIn",
            )
    }
}

tasks.dokkaHtml.configure {
    dokkaSourceSets {
        configureEach {
            reportUndocumented.set(true)
        }
    }
}

signing {
    useGpgCmd()
    setRequired {
        gradle.taskGraph.allTasks.any { it is PublishToMavenRepository }
    }
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}
publishing {
    publications {
        create<MavenPublication>("default") {
            from(components["java"])

            pom {
                name.set(rootProject.name)
                description.set("Awala JVM library")
                url.set("https://github.com/relaycorp/awala-jvm")
                developers {
                    developer {
                        id.set("relaycorp")
                        name.set("Relaycorp, Inc.")
                        email.set("no-reply@relaycorp.tech")
                    }
                }
                licenses {
                    license {
                        name.set("Apache-2.0")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/relaycorp/awala-jvm.git")
                    developerConnection.set("scm:git:https://github.com/relaycorp/awala-jvm.git")
                    url.set("https://github.com/relaycorp/awala-jvm")
                }
            }
        }
    }
    repositories {
        maven {
            url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = System.getenv("MAVEN_USERNAME")
                password = System.getenv("MAVEN_PASSWORD")
            }
        }
    }
}
nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(
                uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"),
            )
            username.set(System.getenv("MAVEN_USERNAME"))
            password.set(System.getenv("MAVEN_PASSWORD"))
        }
    }
}
tasks.publish {
    finalizedBy("closeAndReleaseSonatypeStagingRepository")
}

configure<org.jlleitschuh.gradle.ktlint.KtlintExtension> {
    version.set("1.0.1")
}
