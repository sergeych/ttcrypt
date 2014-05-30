require 'digest/sha1'
require 'securerandom'
require 'openssl'

module TTcrypt

  class RsaKey

    include NumUtils
    extend NumUtils

    def initialize ** kwargs
      @key       = OpenSSL::PKey::RSA.new
      attrs      = %i|n e d p q dp dq q_inv|
      ssl_atttrs = %i|n e d p q|
      kwargs.each { |k, v|
        if attrs.include?(k)
          @key.send("#{k}=", v.to_i) if ssl_atttrs.include?(k)
          instance_variable_set "@#{k}", GMP.Z(v)
        end
      }

      if @p && @q && @e
        # normalize and fill private key components
        @p, @q = @q, @p if @p > @q
        if !@d
          @n     = @p * @q
          @d     = inverse(@e, lcm(@p - 1, @q - 1))
          @dp    = inverse(@e, @p - 1)
          @dq    = inverse(@e, @q - 1)
          @q_inv = inverse(@q, @p)
        end
      end
      @byte_size = bitlength(@n)/8
    end

    def public_ssl_encrypt plaintext
      @key.public_encrypt plaintext, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
    end

    def private_ssl_decrypt plaintext
      @key.private_decrypt plaintext, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
    end

    # RSAES-OAEP-Encrypt with public key; needs (n,e) key components (e.g. public key)
    #
    def public_encrypt plaintext
      em = RsaKey.eme_oaep_encode plaintext, @byte_size-1
      m  = bytes_to_long(em)
      long_to_bytes(m.powmod(@e, @n))
    end

    def private_decrypt plaintext
      c = bytes_to_long plaintext
      raise RsaError, "message too long" if c > @n
      em = if @p && @q
             m1 = c.powmod(@dp, @p)
             m2 = c.powmod(@dq, @q)
             h  = ((m1 - m2) * @q_inv) % @p
             m2 + @q * h
           else
             c.powmod(@d, @n)
           end
      RsaKey.eme_oaep_decode long_to_bytes(em)
    end


    class RsaError < StandardError;
    end

    class <<self
      HLEN=20

      @@seed = nil

      def set_debug_oaep_seed seed
        @@seed = seed.is_a?(String) ? seed : long_to_bytes(seed)
        @@seed.length == HLEN or raise ArgumentError, "seed should be #{HLEN} bytes long, got #{@@seed.length}: #{seed}"
      end

      #
      # eme padding conforms to EME-OAEP-Decode PKCS#1 v2.1
      #
      def eme_oaep_encode message, emLen, p=''
        hLen2 = 2*HLEN
        mLen  = message.length

        raise RsaKey::RsaError, "padded length too small" if emLen <= hLen2 + 1
        raise RsaKey::RsaError, "message too long" if mLen >= emLen - 1 - hLen2 || mLen > emLen - 2 * hLen2 - 1

        ps         = ZERO_CHAR * (emLen - mLen - hLen2 -1)
        pHash      = Digest::SHA1.digest(p)
        db         = pHash + ps + ONE_CHAR + message
        seed       = @@seed || SecureRandom.random_bytes(HLEN)
        dbMask     = mgf(seed, emLen - HLEN)
        maskedDd   = xor(db, dbMask)
        seedMask   = mgf(maskedDd, HLEN)
        maskedSeed = xor(seed, seedMask)
        maskedSeed + maskedDd
      end

      #
      # eme depadding conforms to EME-OAEP-Decode PKCS#1 v2.1
      #
      def eme_oaep_decode em, p=''
        raise DecodeError, 'message is too short!' if em.length < HLEN * 2 + 1

        maskedSeed = em[0...HLEN]
        maskedDB   = em[HLEN..-1]
        seedMask   = mgf maskedDB, HLEN
        seed       = xor maskedSeed, seedMask
        dbMask     = mgf seed, em.size - HLEN
        db         = xor maskedDB, dbMask
        pHash      = Digest::SHA1.digest p

        ind = db.index(ONE_CHAR, HLEN)
        raise RsaError, 'message is invalid!' if ind.nil?

        pHash2 = db[0...HLEN]
        ps     = db[HLEN...ind]
        m      = db[(ind + 1)..-1]

        raise RsaKey::RsaError, 'message is invalid!' unless ps.bytes.all?(&:zero?)
        raise RsaKey::RsaError, "specified p = #{p.inspect} is wrong!" unless pHash2 == pHash
        m
      end

      # Mask generation function, after pkcs#1 v2.1
      def mgf z, l
        t = ''
        (0..(l / HLEN)).each { |i|
          t += Digest::SHA1.digest(z + long_to_bytes(i, 4))
        }
        t[0...l]
      end

    end

  end

end

