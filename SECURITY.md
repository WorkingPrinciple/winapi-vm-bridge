# Security

Report security issues privately through GitHub's security-advisory interface.
Do not open a public issue containing credentials, account identifiers, tokens,
signatures, capabilities, private keys, title secrets, or response bodies.

The bridge uses an operation allowlist. Arbitrary DLL export invocation is out
of scope. Adapters must authenticate transport, bind handles to sessions, bound
inputs, preserve native errors, and avoid secret logging/persistence.

