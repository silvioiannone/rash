# rash

A small CLI hashing utility, written in Rust.

## Features

- Hash generation
- Hash comparison
- Hash verification

## Usage

```
rash <ALGO> [OPTIONS]
```

Reads from a file (`-f/--file`) or stdin, and prints the hash. It can instead
compare a computed hash against an expected one, or just verify a hash's
format.

| Option                 | Description                                                            |
| ---------------------- | ---------------------------------------------------------------------- |
| `-f, --file <FILE>`    | Hash this file instead of stdin.                                       |
| `-c, --compare <HASH>` | Compare the input's hash against `<HASH>`; exits non-zero on mismatch. |
| `-v, --verify <HASH>`  | Only check that `<HASH>` is well-formed for the chosen algorithm.      |

Supported algorithms: `md5`, `sha256`, `sha224`.
