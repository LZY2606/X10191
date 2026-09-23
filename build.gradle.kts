plugins {
    kotlin("jvm") version "2.4.0"
    application
}

repositories { mavenCentral() }

dependencies {
    implementation("io.ktor:ktor-server-core:3.2.3")
    implementation("io.ktor:ktor-server-netty:3.2.3")
    implementation("io.ktor:ktor-server-html-builder:3.2.3")
    implementation("org.xerial:sqlite-jdbc:3.46.1.3")
    implementation("org.slf4j:slf4j-simple:2.0.16")
    testImplementation(kotlin("test"))
    testImplementation("io.ktor:ktor-server-test-host:3.2.3")
}

kotlin { jvmToolchain(17) }

application {
    mainClass.set("compass.MainKt")
}

tasks.test { useJUnitPlatform() }
