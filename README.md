# Active Directory Domain Controller Discovery Tool

A Ruby-based tool for discovering Active Directory domain controllers on a network.

## Features

- Multiple discovery methods (DNS SRV, common names, environment variables)
- LDAP connectivity verification
- Detailed reporting of discovered controllers
- Network troubleshooting hints

## Installation

```bash
gem install net-ldap
```

## Usage

```bash
ruby find_domain_controller.rb
```

## Discovery Methods

1. **DNS SRV Records** - Queries standard AD SRV records
2. **Common Hostnames** - Checks typical DC naming patterns
3. **Environment Variables** - Examines system environment for DC information
4. **DNS A Records** - Looks up common LDAP-related DNS entries

## Requirements

- Ruby 3.0+
- net-ldap gem

## Use Cases

- Network administration
- Security auditing
- AD connectivity troubleshooting
- Domain controller inventory

## License

For authorized security testing and network administration only.