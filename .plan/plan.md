# 行址罗盘 (Address Compass)

## Layers
1. build: Gradle wrapper + build.gradle.kts (Kotlin, Ktor Netty, sqlite-jdbc, JUnit5)
2. ELF parser: header/sections/segments, byte digest, bounds-safe reader
3. DWARF core: CU/abbrev/DIE decode, forms, refs, rangelists v4/v5, addr/str-offsets
4. Line program: v4/v5 headers, state machine, sequences; inline tree
5. Resolver: candidates (narrowest range, inline depth, priority, stable tiebreak), bias/gen
6. Model/DB: SQLite versions, modules, snapshots, crash batches
7. Web: Ktor JSON API + static UI (section map, ranges, line states, inline tree, batch)
8. Fixtures + tests: generated minimal ELF/DWARF; all required cases
9. Verify: build -x test, test, run, UI shows 行址罗盘
