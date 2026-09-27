plugins {
    kotlin("jvm") version "2.2.20"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-core-jvm:2.3.13")
    implementation("io.ktor:ktor-server-cio-jvm:2.3.13")
    implementation("ch.qos.logback:logback-classic:1.4.14")
    implementation("org.xerial:sqlite-jdbc:3.47.1.0")

    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testImplementation("io.ktor:ktor-server-test-host-jvm:2.3.13")
}

application {
    mainClass.set("compass.MainKt")
}

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}
