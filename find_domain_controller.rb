#!/usr/bin/env ruby

require 'resolv'
require 'net/ldap'
require 'socket'

class DomainControllerFinder
  def initialize
    @found_servers = []
  end

  def find_domain_controllers
    puts "Searching for Active Directory Domain Controllers..."
    puts "=" * 50
    
    # Get domain information
    domain = get_domain_name
    puts "Domain detected: #{domain || 'None'}\n\n"
    
    # Method 1: DNS SRV Records (most reliable)
    find_via_dns_srv(domain) if domain
    
    # Method 2: Common hostnames
    find_via_common_names(domain) if domain
    
    # Method 3: Environment variables
    find_via_environment
    
    # Method 4: DNS lookups for common patterns
    find_via_dns_patterns(domain) if domain
    
    # Display results
    display_results
  end

  private

  def get_domain_name
    # Try multiple methods to get domain name
    domain = nil
    
    # Method 1: From hostname command
    domain ||= `hostname -d 2>/dev/null`.strip
    domain = nil if domain.empty?
    
    # Method 2: From environment variable
    domain ||= ENV['USERDNSDOMAIN']&.downcase
    
    # Method 3: Parse from computer's FQDN
    if domain.nil? || domain.empty?
      fqdn = Socket.gethostname
      parts = fqdn.split('.')
      domain = parts[1..-1].join('.') if parts.length > 1
    end
    
    domain
  end

  def find_via_dns_srv(domain)
    puts "Method 1: Checking DNS SRV records..."
    
    dns = Resolv::DNS.new
    
    # Standard AD SRV records
    srv_records = [
      "_ldap._tcp.dc._msdcs.#{domain}",
      "_ldap._tcp.#{domain}",
      "_kerberos._tcp.#{domain}",
      "_gc._tcp.#{domain}"
    ]
    
    srv_records.each do |srv|
      begin
        dns.getresources(srv, Resolv::DNS::Resource::IN::SRV).each do |record|
          server = record.target.to_s
          port = record.port
          
          if test_ldap_connection(server, port)
            @found_servers << { host: server, port: port, method: 'DNS SRV' }
            puts "  ✓ Found DC via SRV: #{server}:#{port}"
          end
        end
      rescue => e
        # Silent fail, try next
      end
    end
  end

  def find_via_common_names(domain)
    puts "\nMethod 2: Checking common DC hostnames..."
    
    common_prefixes = ['dc', 'dc1', 'dc2', 'ad', 'ldap', 'pdc', 'bdc']
    possible_hosts = []
    
    # Build list of possible hostnames
    common_prefixes.each do |prefix|
      possible_hosts << "#{prefix}.#{domain}"
    end
    possible_hosts << domain
    
    possible_hosts.uniq.each do |host|
      if test_ldap_connection(host, 389)
        @found_servers << { host: host, port: 389, method: 'Common Name' }
        puts "  ✓ Found DC: #{host}"
      end
    end
  end

  def find_via_environment
    puts "\nMethod 3: Checking environment variables..."
    
    # Check LOGONSERVER variable
    if ENV['LOGONSERVER']
      server = ENV['LOGONSERVER'].gsub('\\', '')
      if test_ldap_connection(server, 389)
        @found_servers << { host: server, port: 389, method: 'Environment' }
        puts "  ✓ Found DC from LOGONSERVER: #{server}"
      end
    end
    
    # Check LDAPSERVER variable if exists
    if ENV['LDAPSERVER']
      server = ENV['LDAPSERVER']
      if test_ldap_connection(server, 389)
        @found_servers << { host: server, port: 389, method: 'Environment' }
        puts "  ✓ Found DC from LDAPSERVER: #{server}"
      end
    end
  end

  def find_via_dns_patterns(domain)
    puts "\nMethod 4: Checking DNS A records..."
    
    dns = Resolv::DNS.new
    patterns = [
      "_ldap.#{domain}",
      "ldap.#{domain}",
      "ad.#{domain}"
    ]
    
    patterns.each do |pattern|
      begin
        addresses = dns.getaddresses(pattern)
        addresses.each do |addr|
          if test_ldap_connection(addr.to_s, 389)
            @found_servers << { host: pattern, port: 389, method: 'DNS A Record', ip: addr.to_s }
            puts "  ✓ Found DC via DNS: #{pattern} (#{addr})"
          end
        end
      rescue => e
        # Silent fail
      end
    end
  end

  def test_ldap_connection(host, port)
    return false if host.nil? || host.empty?
    
    begin
      # First test TCP connection
      timeout = 2
      Socket.tcp(host, port, connect_timeout: timeout) do |sock|
        sock.close
      end
      
      # Then test LDAP bind (will fail auth but proves LDAP is running)
      ldap = Net::LDAP.new(
        host: host,
        port: port,
        auth: {
          method: :anonymous
        }
      )
      
      # Try anonymous bind first
      result = ldap.bind
      
      # If anonymous fails, try a fake auth (just to verify LDAP responds)
      unless result
        ldap = Net::LDAP.new(
          host: host,
          port: port,
          auth: {
            method: :simple,
            username: "test@example.com",
            password: "test"
          }
        )
        ldap.bind # Will fail but confirms LDAP service
      end
      
      true
    rescue => e
      false
    end
  end

  def display_results
    puts "\n" + "=" * 50
    puts "RESULTS:"
    puts "=" * 50
    
    if @found_servers.empty?
      puts "No Active Directory Domain Controllers found."
      puts "\nPossible reasons:"
      puts "  - Not connected to domain network"
      puts "  - DNS not configured properly"
      puts "  - Firewall blocking LDAP ports (389/636)"
      puts "  - Not running on domain-joined machine"
    else
      puts "Found #{@found_servers.uniq.length} Domain Controller(s):\n\n"
      
      @found_servers.uniq.each_with_index do |server, index|
        puts "#{index + 1}. #{server[:host]}:#{server[:port]}"
        puts "   Discovery Method: #{server[:method]}"
        puts "   IP Address: #{server[:ip]}" if server[:ip]
        puts ""
      end
      
      puts "\nYou can test connectivity with:"
      puts "  ldapsearch -H ldap://#{@found_servers.first[:host]}:#{@found_servers.first[:port]} -x -s base"
    end
  end
end

# Run the finder
if __FILE__ == $0
  begin
    finder = DomainControllerFinder.new
    finder.find_domain_controllers
  rescue LoadError => e
    puts "Error: Missing required gem"
    puts "Please install: gem install net-ldap"
    puts "Error details: #{e.message}"
  rescue => e
    puts "Unexpected error: #{e.message}"
    puts e.backtrace
  end
end