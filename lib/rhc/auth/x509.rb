module RHC::Auth
  class X509
    def initialize(*args)
      @options = args[0] || Commander::Command::Options.new
    end

    def to_request(request)
      request[:client_cert] = certificate_file(options.ssl_client_cert_file)
      # TODO: read passphrase if necessary
      # TODO: support dsa
      request[:client_key] = rsa_key_file(options.ssl_client_key_file)
      request
    end

    def certificate_file(file)
      file && OpenSSL::X509::Certificate.new(IO.read(File.expand_path(file)))
    rescue => e
      debug e
      raise OptionParser::InvalidOption.new(nil, "The certificate '#{file}' cannot be loaded: #{e.message} (#{e.class})")
    end

    def rsa_key_file(file)
      file && OpenSSL::PKey::RSA.new(IO.read(File.expand_path(file)))
    rescue => e
      debug e
      raise OptionParser::InvalidOption.new(nil, "The RSA key '#{file}' cannot be loaded: #{e.message} (#{e.class})")
    end

    def retry_auth?(response, client)
      if response.status == 401
        error "Client certificate was rejected"
      end
      false
    end

    protected
      include RHC::Helpers
      attr_reader :options, :password

    # TODO
  end
end
