# Execute the complete provider allocator regression on Windows ARM64

Windows physical bootstrap run 43143660168 at 4477b8f failed its ARM64 scope
checks before native WFP execution. The actual allocator regression invoked
`go test -race`, and Go returned `-race is not supported on windows/arm64` for
both the unchanged implementation and its two causal mutations.

The runner now asks the selected Go compiler for its effective GOOS/GOARCH. It
omits only the unsupported race flag for Windows ARM64. Every original positive
allocator verdict, both broken allocators, original execution deadlines and
error assertions remain required. Other targets retain the race flag.

Two focused runner tests pass in 3.640 seconds. One executes the actual allocator
and mutations with the normal Linux race build. The other supplies only the
Windows ARM64 compiler-target observation while actually compiling/executing all
three fixtures on the local host without race, verifies all three invocations
occur, and preserves their original timeout/count arguments. This is evidence
for target selection and complete execution, not Windows ARM64 or WFP acceptance;
the hosted ARM64 gate remains required.
