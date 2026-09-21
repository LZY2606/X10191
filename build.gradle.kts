plugins {
    kotlin("jvm") version "2.1.21"
    application
}

repositories { mavenCentral() }

dependencies {
    implementation("io.ktor:ktor-server-core:3.1.3")
    implementation("io.ktor:ktor-server-netty:3.1.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.1.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.1.3")
    implementation("org.xerial:sqlite-jdbc:3.49.1.0")
    implementation("org.slf4j:slf4j-simple:2.0.16")
    testImplementation(kotlin("test"))
}

kotlin { jvmToolchain(17) }

application {
    mainClass.set("compass.MainKt")
}

tasks.test { useJUnitPlatform() }
