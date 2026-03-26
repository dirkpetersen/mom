# Fuzz Testing

Fuzz targets for security-critical parsing functions.

## Setup

```bash
cargo install cargo-fuzz
```

## Running

```bash
# Fuzz package name validation
cargo fuzz run fuzz_package_name

# Fuzz deny list parsing
cargo fuzz run fuzz_deny_list
```

## Targets

- `fuzz_package_name` — exercises `is_valid_package_name()` with arbitrary byte strings
- `fuzz_deny_list` — exercises `DenyList::parse()` with arbitrary input
