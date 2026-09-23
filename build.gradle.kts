plugins {
    kotlin("jvm") version "2.4.20"
    application
}

group = "addresscompass"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    val ktorVersion = "3.6.0"
    implementation("io.ktor:ktor-server-core-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-cio-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation-jvm:$ktorVersion")
    implementation("io.ktor:ktor-serialization-jackson-jvm:$ktorVersion")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.18.2")
    implementation("org.xerial:sqlite-jdbc:3.49.1.0")
    implementation("org.slf4j:slf4j-api:2.0.17")
    implementation("ch.qos.logback:logback-classic:1.5.18")

    testImplementation(kotlin("test"))
}

application {
    mainClass.set("addresscompass.MainKt")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

kotlin {
    jvmToolchain(17)
}
