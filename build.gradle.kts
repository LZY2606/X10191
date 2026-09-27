plugins {
    kotlin("jvm") version "1.9.25"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-core:2.3.12")
    implementation("io.ktor:ktor-server-netty:2.3.12")
    implementation("io.ktor:ktor-server-content-negotiation:2.3.12")
    implementation("io.ktor:ktor-serialization-kotlinx-json:2.3.12")
    implementation("io.ktor:ktor-server-resources:2.3.12")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("org.xerial:sqlite-jdbc:3.46.1.3")
    implementation("ch.qos.logback:logback-classic:1.4.14")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("compass.MainKt")
}

tasks.test {
    useJUnitPlatform()
}
